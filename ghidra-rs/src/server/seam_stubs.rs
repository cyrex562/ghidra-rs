//! Minimal placeholder traits for core types not yet ported, used to break
//! dependency cycles. Each placeholder is replaced by the real port later.

/// Placeholder for `ghidra.server.UserManager`, needed by
/// [`AuthenticationModule`](crate::server::security::AuthenticationModule).
///
/// `AuthenticationModule.authenticate` only ever receives this type to hand along to concrete
/// implementations (e.g. a password-file authentication module validates credentials against
/// it); the interface itself never calls a method on it, so this is a marker trait until the
/// real user manager is ported.
pub trait UserManagerLike: Send + Sync {}

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
