use crate::generic::random::secure_random_factory::SecureRandomFactory;
use crate::net::seam_stubs::{HttpClientsLike, KeyManagerFactoryLike, TrustManagerFactoryLike};
use crate::util::msg::Msg;

/// Port of `ghidra.net.DefaultSSLContextInitializer`.
///
/// Initializes the default JDK `SSLContext` used by all SSL/TLS connections (e.g. https). There
/// is no portable Rust equivalent of a cached `javax.net.ssl.SSLContext` in this crate, so the
/// cached-context state itself is left to the implementor via
/// [`has_cached_context`](Self::has_cached_context) /
/// [`install_cached_context`](Self::install_cached_context) /
/// [`build_and_install_context`](Self::build_and_install_context). Its two real Java
/// collaborators, `DefaultKeyManagerFactory` and `DefaultTrustManagerFactory`, plus
/// `HttpClients`, aren't ported yet, so they're expressed as the minimal
/// [`KeyManagerFactoryLike`], [`TrustManagerFactoryLike`] and [`HttpClientsLike`] seam traits in
/// `seam_stubs.rs` rather than depended on directly, which is what made this type a cycle
/// cut-point.
///
/// Implementors are also expected to implement
/// [`ModuleInitializer`](crate::framework::ModuleInitializer); that supertrait isn't required
/// here so this trait stays free of the coupling being cut, matching the precedent set by
/// [`FileSystemInitializer`](crate::framework::store::file_system_initializer::FileSystemInitializer).
pub trait DefaultSslContextInitializer {
    /// Returns the key manager factory seam used by [`initialize`](Self::initialize) and
    /// [`initialize_with_reset`](Self::initialize_with_reset).
    fn key_manager_factory(&self) -> &dyn KeyManagerFactoryLike;

    /// Returns the trust manager factory seam used by [`initialize`](Self::initialize) and
    /// [`initialize_with_reset`](Self::initialize_with_reset).
    fn trust_manager_factory(&self) -> &dyn TrustManagerFactoryLike;

    /// Returns the `HttpClients` seam used by [`initialize`](Self::initialize).
    fn http_clients(&self) -> &dyn HttpClientsLike;

    /// True once a default `SSLContext` has already been built and cached by a prior
    /// [`initialize`](Self::initialize) call.
    fn has_cached_context(&self) -> bool;

    /// Reinstalls the already-cached `SSLContext` as the process default. Only called when
    /// [`has_cached_context`](Self::has_cached_context) is `true`.
    fn install_cached_context(&self);

    /// Discards the cached `SSLContext`, mirroring `initialize(boolean reset)` setting the
    /// static `sslContext` field back to `null` so the next [`initialize`](Self::initialize) call
    /// rebuilds from scratch.
    fn clear_cached_context(&self);

    /// Builds a new default `SSLContext` from the current key/trust managers, installs it as the
    /// process default, caches it for future calls, and installs the default `HostnameVerifier`
    /// (see [`HttpsHostnameVerifier`]). Returns `true` on success, `false` on failure (with the
    /// failure already logged, mirroring the Java method's caught-and-logged `Exception`).
    fn build_and_install_context(&self) -> bool;

    /// Port of `initialize(boolean reset)`. This method is primarily intended for testing.
    fn initialize_with_reset(&self, reset: bool) -> bool {
        if reset {
            self.clear_cached_context();
            self.trust_manager_factory().invalidate_trust_managers();
            self.key_manager_factory().invalidate_key_manager();
        }
        self.initialize()
    }

    /// Port of `initialize()`.
    fn initialize(&self) -> bool {
        if self.has_cached_context() {
            self.install_cached_context();
            return true;
        }

        Msg::info(&self.get_name(), &"Initializing SSL Context");

        let _key_manager = self.key_manager_factory().get_key_manager();
        // Touch the shared secure random source, mirroring `SecureRandomFactory.getSecureRandom()`
        // being pulled in to seed `SSLContext.init(...)`.
        let _ = SecureRandomFactory::get_secure_random();
        let _trust_managers = self.trust_manager_factory().get_trust_managers();

        let built = self.build_and_install_context();
        if built {
            // Force the HttpClient to be re-created by the next request so the new SSLContext is used.
            self.http_clients().clear_http_client();
        }
        built
    }

    /// Port of `run()`.
    fn run(&self) {
        self.initialize();
    }

    /// Port of `getName()`.
    fn get_name(&self) -> String {
        "SSL Context".to_string()
    }
}

/// Port of the nested `DefaultSSLContextInitializer.HttpsHostnameVerifier` class.
///
/// Required by `HttpsURLConnection` even though it always rejects: the verify method is only
/// invoked if the default hostname-matching behavior already failed the connection attempt.
#[derive(Debug, Default, Clone, Copy)]
pub struct HttpsHostnameVerifier;

impl HttpsHostnameVerifier {
    /// Port of `HttpsHostnameVerifier.verify(String hostname, SSLSession session)`. The Java
    /// session parameter carries no information this method uses, so it is omitted here.
    pub fn verify(&self, _hostname: &str) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    #[derive(Default)]
    struct MockKeyManagerFactory {
        invalidated: Cell<bool>,
    }

    impl KeyManagerFactoryLike for MockKeyManagerFactory {
        fn get_key_manager(&self) -> bool {
            true
        }

        fn invalidate_key_manager(&self) {
            self.invalidated.set(true);
        }
    }

    #[derive(Default)]
    struct MockTrustManagerFactory {
        invalidated: Cell<bool>,
    }

    impl TrustManagerFactoryLike for MockTrustManagerFactory {
        fn get_trust_managers(&self) -> bool {
            true
        }

        fn invalidate_trust_managers(&self) {
            self.invalidated.set(true);
        }
    }

    #[derive(Default)]
    struct MockHttpClients {
        cleared: Cell<bool>,
    }

    impl HttpClientsLike for MockHttpClients {
        fn clear_http_client(&self) {
            self.cleared.set(true);
        }
    }

    #[derive(Default)]
    struct TestInitializer {
        key_manager_factory: MockKeyManagerFactory,
        trust_manager_factory: MockTrustManagerFactory,
        http_clients: MockHttpClients,
        cached: RefCell<bool>,
        installs: Cell<u32>,
        builds: Cell<u32>,
        build_should_succeed: Cell<bool>,
    }

    impl DefaultSslContextInitializer for TestInitializer {
        fn key_manager_factory(&self) -> &dyn KeyManagerFactoryLike {
            &self.key_manager_factory
        }

        fn trust_manager_factory(&self) -> &dyn TrustManagerFactoryLike {
            &self.trust_manager_factory
        }

        fn http_clients(&self) -> &dyn HttpClientsLike {
            &self.http_clients
        }

        fn has_cached_context(&self) -> bool {
            *self.cached.borrow()
        }

        fn install_cached_context(&self) {
            self.installs.set(self.installs.get() + 1);
        }

        fn clear_cached_context(&self) {
            *self.cached.borrow_mut() = false;
        }

        fn build_and_install_context(&self) -> bool {
            self.builds.set(self.builds.get() + 1);
            let ok = self.build_should_succeed.get();
            if ok {
                *self.cached.borrow_mut() = true;
            }
            ok
        }
    }

    #[test]
    fn initialize_builds_and_caches_on_first_call() {
        let init = TestInitializer::default();
        init.build_should_succeed.set(true);

        assert!(!init.has_cached_context());
        assert!(init.initialize());
        assert_eq!(init.builds.get(), 1);
        assert_eq!(init.installs.get(), 0);
        assert!(init.http_clients.cleared.get());
        assert!(init.has_cached_context());
    }

    #[test]
    fn initialize_reuses_cached_context_on_subsequent_calls() {
        let init = TestInitializer::default();
        init.build_should_succeed.set(true);

        assert!(init.initialize());
        assert!(init.initialize());

        assert_eq!(init.builds.get(), 1);
        assert_eq!(init.installs.get(), 1);
    }

    #[test]
    fn initialize_returns_false_and_skips_http_clear_on_build_failure() {
        let init = TestInitializer::default();
        init.build_should_succeed.set(false);

        assert!(!init.initialize());
        assert!(!init.has_cached_context());
        assert!(!init.http_clients.cleared.get());
    }

    #[test]
    fn initialize_with_reset_true_invalidates_managers_and_rebuilds() {
        let init = TestInitializer::default();
        init.build_should_succeed.set(true);
        assert!(init.initialize());
        assert!(init.has_cached_context());

        assert!(init.initialize_with_reset(true));

        assert!(init.trust_manager_factory.invalidated.get());
        assert!(init.key_manager_factory.invalidated.get());
        // Reset cleared the cache, so this call rebuilt from scratch instead of reinstalling.
        assert_eq!(init.builds.get(), 2);
        assert_eq!(init.installs.get(), 0);
    }

    #[test]
    fn get_name_matches_java_module_name() {
        let init = TestInitializer::default();
        assert_eq!(init.get_name(), "SSL Context");
    }

    #[test]
    fn run_delegates_to_initialize() {
        let init = TestInitializer::default();
        init.build_should_succeed.set(true);
        init.run();
        assert_eq!(init.builds.get(), 1);
    }

    #[test]
    fn is_object_safe() {
        let init = TestInitializer::default();
        init.build_should_succeed.set(true);
        let dyn_init: &dyn DefaultSslContextInitializer = &init;

        assert_eq!(dyn_init.get_name(), "SSL Context");
        assert!(dyn_init.initialize());
    }

    #[test]
    fn https_hostname_verifier_always_rejects() {
        let verifier = HttpsHostnameVerifier;
        assert!(!verifier.verify("example.com"));
        assert!(!verifier.verify(""));
    }
}
