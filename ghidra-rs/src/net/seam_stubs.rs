//! Minimal placeholder traits for core types that a ported interface references before the real
//! Rust port of that type exists yet. Each stub exposes only the members needed by the
//! interface(s) that currently reference it, and is expected to be replaced (or grown into a
//! supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for provenance.

/// Placeholder for `ghidra.net.DefaultKeyManagerFactory`, referenced by
/// [`DefaultSslContextInitializer`](crate::net::default_ssl_context_initializer::DefaultSslContextInitializer)
/// before the real port exists. The Java class carries keystore path/password preferences,
/// self-signed-certificate generation, and signature helpers; only the key-manager lookup and
/// invalidation used by the SSL context bootstrap are declared here.
pub trait KeyManagerFactoryLike {
    /// Mirrors `DefaultKeyManagerFactory.getKeyManager()`. Returns `true` if a key manager was
    /// obtained (lazily creating one, as the Java method does, is left to the implementor).
    fn get_key_manager(&self) -> bool;

    /// Mirrors `DefaultKeyManagerFactory.invalidateKeyManager()`.
    fn invalidate_key_manager(&self);
}

/// Placeholder for `ghidra.net.DefaultTrustManagerFactory`, referenced by
/// [`DefaultSslContextInitializer`](crate::net::default_ssl_context_initializer::DefaultSslContextInitializer)
/// before the real port exists. Only the trust-manager lookup and invalidation used by the SSL
/// context bootstrap are declared here.
pub trait TrustManagerFactoryLike {
    /// Mirrors `DefaultTrustManagerFactory.getTrustManagers()`. Returns `true` if trust managers
    /// were obtained.
    fn get_trust_managers(&self) -> bool;

    /// Mirrors `DefaultTrustManagerFactory.invalidateTrustManagers()`.
    fn invalidate_trust_managers(&self);
}

/// Placeholder for `ghidra.net.HttpClients`, referenced by
/// [`DefaultSslContextInitializer`](crate::net::default_ssl_context_initializer::DefaultSslContextInitializer)
/// before the real port exists. Only the cache-clearing hook used after a new default
/// `SSLContext` is installed is declared here.
pub trait HttpClientsLike {
    /// Mirrors `HttpClients.clearHttpClient()`.
    fn clear_http_client(&self);
}
