use crate::filesystem::seam_stubs::FsrlLike;
use crate::framework::generic::auth::password::Password;

/// Provides the caller with the ability to perform crypto querying operations
/// for a group of related files.
///
/// Typically used to query passwords and to add known good passwords
/// to caches for later re-retrieval.
///
/// Closing a [`CryptoSession`] instance does not invalidate the instance, instead it is a
/// suggestion that the instance should not be used for any further nested sessions.
///
/// See `CryptoProviders::new_session()` (ported separately).
pub trait CryptoSession<Fsrl: FsrlLike> {
    /// Returns a sequence of passwords (sorted by quality) that may apply to
    /// the specified file.
    ///
    /// `fsrl` is the path to the password protected file; `prompt` is an optional prompt that
    /// may be displayed to a user.
    fn get_passwords_for<'a>(
        &'a self,
        fsrl: &'a Fsrl,
        prompt: &str,
    ) -> Box<dyn Iterator<Item = Password> + 'a>;

    /// Pushes a known good password into a cache for later re-retrieval.
    ///
    /// `fsrl` is the path to the file that was unlocked by `password`.
    fn add_successful_password(&mut self, fsrl: &Fsrl, password: Password);

    /// Returns true if this session has been closed.
    fn is_closed(&self) -> bool;

    /// Closes this session.
    fn close(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockFsrl {
        path: String,
    }
    impl FsrlLike for MockFsrl {}

    struct MockCryptoSession {
        known_good: Vec<(String, Password)>,
        closed: bool,
    }

    impl MockCryptoSession {
        fn new() -> Self {
            MockCryptoSession { known_good: Vec::new(), closed: false }
        }
    }

    impl CryptoSession<MockFsrl> for MockCryptoSession {
        fn get_passwords_for<'a>(
            &'a self,
            fsrl: &'a MockFsrl,
            _prompt: &str,
        ) -> Box<dyn Iterator<Item = Password> + 'a> {
            Box::new(
                self.known_good
                    .iter()
                    .filter(move |(path, _)| path == &fsrl.path)
                    .map(|(_, pw)| pw.clone()),
            )
        }

        fn add_successful_password(&mut self, fsrl: &MockFsrl, password: Password) {
            self.known_good.push((fsrl.path.clone(), password));
        }

        fn is_closed(&self) -> bool {
            self.closed
        }

        fn close(&mut self) {
            self.closed = true;
        }
    }

    #[test]
    fn object_safety_via_boxed_dyn() {
        let session: Box<dyn CryptoSession<MockFsrl>> = Box::new(MockCryptoSession::new());
        assert!(!session.is_closed());
    }

    #[test]
    fn add_then_retrieve_successful_password() {
        let mut session = MockCryptoSession::new();
        let fsrl = MockFsrl { path: "/archive/secret.zip".to_string() };
        let pw = Password::copy_of(&"hunter2".chars().collect::<Vec<_>>());

        session.add_successful_password(&fsrl, pw.clone());

        let found: Vec<Password> = session.get_passwords_for(&fsrl, "unlock").collect();
        assert_eq!(found, vec![pw]);
    }

    #[test]
    fn passwords_scoped_to_matching_fsrl() {
        let mut session = MockCryptoSession::new();
        let a = MockFsrl { path: "/a.zip".to_string() };
        let b = MockFsrl { path: "/b.zip".to_string() };
        session.add_successful_password(&a, Password::copy_of(&['x']));

        let found: Vec<Password> = session.get_passwords_for(&b, "unlock").collect();
        assert!(found.is_empty());
    }

    #[test]
    fn close_marks_session_closed() {
        let mut session = MockCryptoSession::new();
        assert!(!session.is_closed());
        session.close();
        assert!(session.is_closed());
    }
}
