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
