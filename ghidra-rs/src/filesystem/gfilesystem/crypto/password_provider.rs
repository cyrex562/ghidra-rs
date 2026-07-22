use crate::filesystem::gfilesystem::crypto::crypto_provider::{CryptoProvider, Session};
use crate::filesystem::seam_stubs::FsrlLike;
use crate::framework::generic::auth::password::Password;

/// Instances of this trait provide passwords to decrypt files.
///
/// Instances are typically not called directly, instead are used by a
/// [`CryptoSession`](crate::filesystem::gfilesystem::crypto::crypto_session::CryptoSession)
/// along with other provider instances to provide a balanced breakfast.
///
/// Multiple passwords can be returned for each request with the assumption that the consumer
/// of the values can test and validate each one to find the correct value. Conversely, it would
/// not be appropriate to use this to get a password for a login service that may lock the
/// requester out after a small number of failed attempts.
pub trait PasswordProvider<Fsrl: FsrlLike, CP, S: Session<CP>>: CryptoProvider {
    /// Returns a sequence of passwords (ordered by quality) that may apply to the specified
    /// file.
    ///
    /// `fsrl` is the path to the password protected file; `prompt` is an optional prompt that
    /// may be displayed to a user; `session` is a place to hold state values that persist
    /// across related queries.
    fn get_passwords_for<'a>(
        &'a self,
        fsrl: &'a Fsrl,
        prompt: &str,
        session: &mut S,
    ) -> Box<dyn Iterator<Item = Password> + 'a>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;
    use std::collections::HashMap;

    struct MockFsrl {
        path: String,
    }
    impl FsrlLike for MockFsrl {}

    struct MockProviders {
        id: u32,
    }

    struct MockSession {
        providers: MockProviders,
        state: HashMap<usize, Box<dyn Any>>,
    }

    impl MockSession {
        fn new(providers: MockProviders) -> Self {
            MockSession {
                providers,
                state: HashMap::new(),
            }
        }
    }

    fn provider_key(p: &dyn CryptoProvider) -> usize {
        p as *const dyn CryptoProvider as *const () as usize
    }

    impl Session<MockProviders> for MockSession {
        fn set_state_value(&mut self, crypto_provider: &dyn CryptoProvider, value: Box<dyn Any>) {
            self.state.insert(provider_key(crypto_provider), value);
        }

        fn get_state_value<T: 'static>(
            &mut self,
            crypto_provider: &dyn CryptoProvider,
            state_factory: impl FnOnce() -> T,
        ) -> T {
            let key = provider_key(crypto_provider);
            match self.state.remove(&key) {
                Some(boxed) => *boxed.downcast::<T>().expect("type mismatch in get_state_value"),
                None => state_factory(),
            }
        }

        fn get_crypto_providers(&self) -> &MockProviders {
            &self.providers
        }
    }

    /// A provider that always returns a fixed set of candidate passwords, in order,
    /// mirroring something like `CmdLinePasswordProvider`.
    struct FixedPasswordProvider {
        candidates: Vec<Password>,
    }
    impl CryptoProvider for FixedPasswordProvider {}

    impl PasswordProvider<MockFsrl, MockProviders, MockSession> for FixedPasswordProvider {
        fn get_passwords_for<'a>(
            &'a self,
            _fsrl: &'a MockFsrl,
            _prompt: &str,
            _session: &mut MockSession,
        ) -> Box<dyn Iterator<Item = Password> + 'a> {
            Box::new(self.candidates.iter().cloned())
        }
    }

    #[test]
    fn object_safety_via_boxed_dyn() {
        let provider: Box<dyn PasswordProvider<MockFsrl, MockProviders, MockSession>> =
            Box::new(FixedPasswordProvider {
                candidates: vec![Password::copy_of(&['a'])],
            });
        let fsrl = MockFsrl { path: "/archive/secret.zip".to_string() };
        let mut session = MockSession::new(MockProviders { id: 1 });

        let found: Vec<Password> = provider
            .get_passwords_for(&fsrl, "unlock", &mut session)
            .collect();
        assert_eq!(found, vec![Password::copy_of(&['a'])]);
    }

    #[test]
    fn returns_passwords_ordered_by_quality() {
        let provider = FixedPasswordProvider {
            candidates: vec![
                Password::copy_of(&"best".chars().collect::<Vec<_>>()),
                Password::copy_of(&"worst".chars().collect::<Vec<_>>()),
            ],
        };
        let fsrl = MockFsrl { path: "/a.zip".to_string() };
        let mut session = MockSession::new(MockProviders { id: 1 });

        let found: Vec<Password> = provider
            .get_passwords_for(&fsrl, "unlock", &mut session)
            .collect();
        assert_eq!(
            found,
            vec![
                Password::copy_of(&"best".chars().collect::<Vec<_>>()),
                Password::copy_of(&"worst".chars().collect::<Vec<_>>()),
            ]
        );
    }

    #[test]
    fn no_candidates_yields_empty_iterator() {
        let provider = FixedPasswordProvider { candidates: vec![] };
        let fsrl = MockFsrl { path: "/a.zip".to_string() };
        let mut session = MockSession::new(MockProviders { id: 1 });

        let found: Vec<Password> = provider
            .get_passwords_for(&fsrl, "unlock", &mut session)
            .collect();
        assert!(found.is_empty());
    }
}
