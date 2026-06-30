/// Provider of passwords for keystore files.
///
/// Mirrors `ghidra.security.KeyStorePasswordProvider`.
pub trait KeyStorePasswordProvider {
    /// Requests the password for a keystore file.
    ///
    /// Returns `None` if the user cancels or no password is available.
    /// When `Some` is returned, the caller is responsible for zeroing the
    /// characters when they are no longer needed.
    ///
    /// # Arguments
    /// * `keystore_path` - path to the keystore file
    /// * `password_error` - `true` if this is a repeated prompt due to a prior password failure
    fn get_key_store_password(
        &self,
        keystore_path: &str,
        password_error: bool,
    ) -> Option<Vec<char>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct StaticProvider {
        password: Option<Vec<char>>,
        fail_on_error: bool,
    }

    impl KeyStorePasswordProvider for StaticProvider {
        fn get_key_store_password(
            &self,
            _keystore_path: &str,
            password_error: bool,
        ) -> Option<Vec<char>> {
            if password_error && self.fail_on_error {
                return None;
            }
            self.password.clone()
        }
    }

    #[test]
    fn returns_password_on_first_attempt() {
        let provider = StaticProvider {
            password: Some("secret".chars().collect()),
            fail_on_error: false,
        };
        let result = provider.get_key_store_password("/path/to/keystore.p12", false);
        assert_eq!(result, Some("secret".chars().collect::<Vec<char>>()));
    }

    #[test]
    fn returns_none_when_no_password_available() {
        let provider = StaticProvider {
            password: None,
            fail_on_error: false,
        };
        assert!(provider
            .get_key_store_password("/path/to/keystore.p12", false)
            .is_none());
    }

    #[test]
    fn returns_none_on_repeated_password_failure() {
        let provider = StaticProvider {
            password: Some("secret".chars().collect()),
            fail_on_error: true,
        };
        assert!(provider
            .get_key_store_password("/path/to/keystore.p12", true)
            .is_none());
    }

    #[test]
    fn still_returns_password_when_error_flag_false() {
        let provider = StaticProvider {
            password: Some("pass".chars().collect()),
            fail_on_error: true,
        };
        let result = provider.get_key_store_password("/path/to/keystore.p12", false);
        assert_eq!(result, Some("pass".chars().collect::<Vec<char>>()));
    }

    #[test]
    fn keystore_path_is_forwarded_to_implementation() {
        struct PathCapture {
            captured: RefCell<String>,
        }

        impl KeyStorePasswordProvider for PathCapture {
            fn get_key_store_password(
                &self,
                keystore_path: &str,
                _password_error: bool,
            ) -> Option<Vec<char>> {
                *self.captured.borrow_mut() = keystore_path.to_string();
                None
            }
        }

        let provider = PathCapture {
            captured: RefCell::new(String::new()),
        };
        provider.get_key_store_password("/some/path/keystore.p12", false);
        assert_eq!(*provider.captured.borrow(), "/some/path/keystore.p12");
    }
}
