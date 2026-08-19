//! Minimal placeholder traits for core types not yet ported, used to break
//! dependency cycles. Each placeholder is replaced by the real port later.

use std::io;

/// Placeholder for `ghidra.server.UserManager`, needed by
/// [`AuthenticationModule`](crate::server::security::AuthenticationModule) and by
/// [`RepositoryServerHandleImpl`](crate::server::remote::repository_server_handle_impl::RepositoryServerHandleImpl).
///
/// `AuthenticationModule.authenticate` only ever receives this type to hand along to concrete
/// implementations (e.g. a password-file authentication module validates credentials against
/// it); the interface itself never calls a method on it. `RepositoryServerHandleImpl`, however,
/// calls `canSetPassword`/`getPasswordExpiration`/`setPassword` directly on the `UserManager`
/// returned by `RepositoryManager.getUserManager()`, so those three accessors are added here.
pub trait UserManagerLike: Send + Sync {
    /// Returns true if local passwords are in use and can be changed by the given user.
    fn can_set_password(&self, username: &str) -> bool;

    /// Returns the amount of time in milliseconds until the user's password will expire, or -1
    /// if it will not expire.
    fn get_password_expiration(&self, username: &str) -> i64;

    /// Sets the password for the given user. `salted_sha256_password_hash` is a 4-character salt
    /// followed by a 64-hex-digit SHA256 password hash. Returns true if successful, false if the
    /// user was not found.
    fn set_password(
        &self,
        username: &str,
        salted_sha256_password_hash: &[u8],
        is_temporary: bool,
    ) -> io::Result<bool>;
}

/// Placeholder for `ghidra.server.stream.RemoteBlockStreamHandle`, needed by
/// [`BlockStreamServer`](crate::server::stream::BlockStreamServer).
///
/// The Java class is itself constructed with a live `BlockStreamServer` reference, so porting it
/// here would recreate the dependency cycle `BlockStreamServer` was extracted to break. A handle
/// only needs to expose its assigned stream ID and pending-connection state to the server's
/// registration bookkeeping (`registerBlockStream`), so this placeholder captures just those two
/// accessors until the real handle is ported.
pub trait RemoteBlockStreamHandleLike: Send + Sync {
    /// Get the unique ID for this stream.
    fn stream_id(&self) -> u64;

    /// Determine if a connection has not yet been requested for this handle.
    fn is_pending(&self) -> bool;
}

/// Placeholder for `ghidra.server.store.RepositoryFolder`, needed by
/// [`RepositoryFile`](crate::server::store::repository_file::RepositoryFile) before the real
/// class is ported.
///
/// The two Java classes form a direct dependency cycle: `RepositoryFolder` holds a `fileMap` of
/// `RepositoryFile`s and calls back into them, while `RepositoryFile.getParent()` returns its
/// owning `RepositoryFolder` and `RepositoryFile.moveTo()` takes a new `RepositoryFolder` as its
/// destination. `RepositoryFile` was selected as the cycle cut-point, so this placeholder captures
/// only the members `RepositoryFile` needs from its folder: the pathname (used to build its own
/// `getPathname()`, and to report old/new paths on a move) and the two package-private
/// notification callbacks (`fileDeleted`, `fileMoved`) a `RepositoryFile` implementation invokes
/// on its former parent after a delete or move completes.
pub trait RepositoryFolderLike: Send + Sync {
    /// Returns the folder's path within the repository.
    fn get_pathname(&self) -> String;

    /// Notifies this folder that the given file has been deleted, so it can be dropped from the
    /// folder's cached file map.
    fn file_deleted(&self, file: &dyn crate::server::store::repository_file::RepositoryFile);

    /// Notifies this folder that the given file (previously named `old_name`) has moved to
    /// `new_folder`, so it can be dropped from the folder's cached file map.
    fn file_moved(
        &self,
        file: &dyn crate::server::store::repository_file::RepositoryFile,
        old_name: &str,
        new_folder: &dyn RepositoryFolderLike,
    );
}

/// Placeholder for `ghidra.server.Repository`, needed by
/// [`RepositoryHandleImpl`](crate::server::remote::repository_handle_impl::RepositoryHandleImpl).
///
/// `Repository` holds an `ArrayList<RepositoryHandleImpl>` and calls `checkHandle`/
/// `dispatchEvents`/`dispose` directly on the concrete type, while `RepositoryHandleImpl` holds a
/// `Repository` field and calls back into it. `RepositoryHandleImpl` was selected as the cycle
/// cut-point, so this placeholder captures only the members reached through
/// `RepositoryHandleImpl::get_repository()` by its (not yet ported) sibling classes
/// `RemoteBufferFileImpl`/`RemoteManagedBufferFileImpl`: logging a message against an optional
/// folder/item path and user, and reading the repository's name.
pub trait RepositoryLike: Send + Sync {
    /// Append a log entry associated with an optional folder/item path and optional user.
    fn log(&self, path: Option<&str>, msg: &str, user: Option<&str>);

    /// Returns the name of this repository.
    fn get_name(&self) -> String;
}

/// Placeholder for `ghidra.server.RepositoryManager`, needed by
/// [`RepositoryServerHandleImpl`](crate::server::remote::repository_server_handle_impl::RepositoryServerHandleImpl).
///
/// `RepositoryManager` holds an `ArrayList<RepositoryServerHandleImpl>` and calls `addHandle`/
/// `dropHandle` directly on the concrete type from the constructor and RMI `unreferenced()`
/// callback, while `RepositoryServerHandleImpl` holds a `RepositoryManager mgr` field and
/// delegates every `RepositoryServerHandle` method to it. `RepositoryServerHandleImpl` was
/// selected as the cycle cut-point, so this placeholder captures only the members reached through
/// `RepositoryServerHandle`'s own methods: repository create/get/delete/list, the all-users list,
/// the anonymous-access flag, and the nested user manager used for password operations.
/// `addHandle`/`dropHandle` are intentionally omitted -- like the analogous `Repository::addHandle`/
/// `dropHandle` omitted from [`RepositoryLike`] -- since they are driven by construction/RMI
/// lifecycle rather than by any `RepositoryServerHandle` method body.
pub trait RepositoryManagerLike: Send + Sync {
    /// Returns true if server allows anonymous access.
    fn anonymous_access_allowed(&self) -> bool;

    /// Create a new repository on behalf of `current_user`.
    fn create_repository(&self, current_user: &str, name: &str) -> io::Result<Box<dyn RepositoryLike>>;

    /// Get a handle to an existing repository, or `None` if it does not exist.
    fn get_repository(
        &self,
        current_user: &str,
        name: &str,
    ) -> io::Result<Option<Box<dyn RepositoryLike>>>;

    /// Delete the named repository on behalf of `current_user`.
    fn delete_repository(&self, current_user: &str, name: &str) -> io::Result<()>;

    /// Returns the names of all repositories accessible by `current_user`.
    fn get_repository_names(&self, current_user: &str) -> Vec<String>;

    /// Returns the names of all known users, as seen by `current_user`.
    fn get_all_users(&self, current_user: &str) -> Vec<String>;

    /// Returns the server's user manager.
    fn get_user_manager(&self) -> Box<dyn UserManagerLike>;
}
