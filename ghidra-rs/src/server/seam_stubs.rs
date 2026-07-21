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
