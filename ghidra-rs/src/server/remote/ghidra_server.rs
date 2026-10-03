// Port of orig_src/Ghidra/Features/GhidraServer/src/main/java/ghidra/server/remote/GhidraServer.java
//
// Original license header (Apache-2.0, IP: GHIDRA):
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

use crate::framework::remote::GhidraServerHandle;

/// Provides the main Ghidra server application and implements
/// [`GhidraServerHandle`] which facilitates remote access to services provided by a repository
/// manager.
///
/// Mirrors `ghidra.server.remote.GhidraServer`, recast as a trait so implementations can be
/// decoupled from the concrete singleton (was selected as a dependency-cycle cut point:
/// `RepositoryServerHandleImpl`/`RepositoryHandleImpl`/`RemoteBufferFileImpl`, constructed (directly
/// or indirectly) by [`get_repository_server`](GhidraServerHandle::get_repository_server), each in
/// turn call back to `GhidraServer`'s static RMI socket-factory accessors in their own
/// constructors). Those sibling `ghidra.server.remote` classes are not yet ported, so none of them
/// currently need those accessors exposed here; only the genuinely object-level public API
/// (`GhidraServerHandle`'s remote methods, inherited as a supertrait, plus `dispose()`) is captured
/// by this trait. The constructor's authentication-module selection, certificate/keystore setup,
/// and the `main` entry point are startup orchestration for one concrete server process, not part
/// of the interface a caller programs against, so they are intentionally left out -- consistent
/// with how [`BlockStreamServer`](crate::server::stream::BlockStreamServer) omitted its own accept
/// loop and singleton accessor for the same reason.
pub trait GhidraServer: GhidraServerHandle {
    /// Dispose the entire server.
    fn dispose(&self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::remote::{
        GhidraPrincipal, GhidraServerHandleError, RemoteRepositoryServerHandle, RepositoryHandle,
        RepositoryServerHandle,
    };
    use crate::framework::seam_stubs::AuthCallback;
    use std::cell::Cell;
    use std::io;

    struct MockRepositoryServerHandle;

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
            Ok(vec![])
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

    /// Mock server whose `get_repository_server` mirrors the real `GhidraServer`'s post-`dispose`
    /// behavior: once disposed, the server no longer hands out repository server handles (in Java,
    /// `dispose()` nulls out the backing `RepositoryManager`, so any later
    /// `getRepositoryServer` call would fail against a torn-down manager).
    struct MockGhidraServer {
        disposed: Cell<bool>,
    }

    impl GhidraServerHandle for MockGhidraServer {
        fn get_authentication_callbacks(&self) -> io::Result<Option<Vec<Box<dyn AuthCallback>>>> {
            Ok(None)
        }

        fn get_repository_server(
            &self,
            user: Option<&[GhidraPrincipal]>,
            _auth_callbacks: Option<&[Box<dyn AuthCallback>]>,
        ) -> Result<Box<dyn RemoteRepositoryServerHandle>, GhidraServerHandleError> {
            if self.disposed.get() {
                return Err(GhidraServerHandleError::FailedLogin(
                    "server has been disposed".to_string(),
                ));
            }
            if user.unwrap_or(&[]).is_empty() {
                return Err(GhidraServerHandleError::FailedLogin(
                    "no GhidraPrincipal present on subject".to_string(),
                ));
            }
            Ok(Box::new(MockRepositoryServerHandle))
        }

        fn check_compatibility(&self, _client_interface_version: i32) -> io::Result<()> {
            Ok(())
        }
    }

    impl GhidraServer for MockGhidraServer {
        fn dispose(&self) {
            self.disposed.set(true);
        }
    }

    #[test]
    fn test_object_safety_and_dispose_stops_repository_server_access() {
        let server: Box<dyn GhidraServer> =
            Box::new(MockGhidraServer { disposed: Cell::new(false) });

        let principals = vec![GhidraPrincipal::new("alice")];

        // Before disposal, a valid principal is granted a repository server handle.
        assert!(server.get_repository_server(Some(&principals), None).is_ok());

        server.dispose();

        // After disposal, even a valid principal is refused.
        let err = server
            .get_repository_server(Some(&principals), None)
            .err()
            .unwrap();
        assert!(matches!(err, GhidraServerHandleError::FailedLogin(_)));
    }
}
