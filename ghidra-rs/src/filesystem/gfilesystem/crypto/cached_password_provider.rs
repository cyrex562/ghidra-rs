use crate::filesystem::gfilesystem::crypto::crypto_provider::Session;
use crate::filesystem::gfilesystem::crypto::password_provider::PasswordProvider;
use crate::filesystem::gfilesystem::fsrl::Fsrl;
use crate::framework::generic::auth::password::Password;

/// Caches passwords used to unlock a file.
///
/// Mirrors the Java `CachedPasswordProvider`, a concrete [`PasswordProvider`] implementation
/// selected as a cycle cut-point and ported here as a trait. `get_passwords_for` is inherited
/// from [`PasswordProvider`]; this trait adds the cache-population/inspection API
/// (`addPassword`/`clearCache`/`getCount` in Java).
///
/// The Java doc notes instances are threadsafe (methods are `synchronized`); that guarantee is
/// left to implementors here rather than baked into the trait signature.
pub trait CachedPasswordProvider<CP, S: Session<CP>>:
    PasswordProvider<CP, S>
{
    /// Adds a password / file combo to the cache.
    ///
    /// `password` is only copied in; clearing the caller's own copy remains their
    /// responsibility, matching the Java `password.clone()` behavior.
    fn add_password(&mut self, fsrl: &Fsrl, password: &Password);

    /// Removes all cached information.
    fn clear_cache(&mut self);

    /// Returns the number of items in the cache.
    fn get_count(&self) -> usize;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::gfilesystem::crypto::crypto_provider::CryptoProvider;
    use std::any::Any;
    use std::collections::{HashMap, HashSet};

    struct MockProviders;

    struct MockSession {
        providers: MockProviders,
        state: HashMap<usize, Box<dyn Any>>,
    }

    impl MockSession {
        fn new() -> Self {
            MockSession { providers: MockProviders, state: HashMap::new() }
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

    struct CryptoRec {
        id: u64,
        value: Password,
    }

    /// A faithful-enough mirror of the Java implementation's `addRec`/`getPasswordsFor`:
    /// records are indexed under the full FSRL string, its pretty string (if different), its
    /// plain name, and its MD5 (if present), with per-bucket dedup by password value and
    /// cross-bucket dedup by record identity when reading back.
    struct MockCachedPasswordProvider {
        values: HashMap<String, Vec<usize>>,
        records: Vec<CryptoRec>,
        next_id: u64,
        count: usize,
    }
    impl CryptoProvider for MockCachedPasswordProvider {}

    impl MockCachedPasswordProvider {
        fn new() -> Self {
            MockCachedPasswordProvider {
                values: HashMap::new(),
                records: Vec::new(),
                next_id: 0,
                count: 0,
            }
        }

        fn alias_keys(fsrl: &Fsrl) -> Vec<String> {
            let mut keys = vec![fsrl.to_string()];
            let pretty = fsrl.to_pretty_string();
            if pretty != keys[0] {
                keys.push(pretty);
            }
            keys.push(fsrl.name().unwrap_or_default());
            if let Some(md5) = fsrl.md5() {
                keys.push(md5.to_owned());
            }
            keys
        }
    }

    impl PasswordProvider<MockProviders, MockSession> for MockCachedPasswordProvider {
        fn get_passwords_for<'a>(
            &'a self,
            fsrl: &'a Fsrl,
            _prompt: &str,
            _session: &mut MockSession,
        ) -> Box<dyn Iterator<Item = Password> + 'a> {
            let mut seen_ids = HashSet::new();
            let mut results = Vec::new();
            for key in Self::alias_keys(fsrl) {
                if let Some(bucket) = self.values.get(&key) {
                    for &idx in bucket {
                        let rec = &self.records[idx];
                        if seen_ids.insert(rec.id) {
                            results.push(rec.value.clone());
                        }
                    }
                }
            }
            Box::new(results.into_iter())
        }
    }

    impl CachedPasswordProvider<MockProviders, MockSession> for MockCachedPasswordProvider {
        fn add_password(&mut self, fsrl: &Fsrl, password: &Password) {
            let id = self.next_id;
            self.next_id += 1;
            self.records.push(CryptoRec { id, value: password.clone() });
            let idx = self.records.len() - 1;

            let mut is_new_value = false;
            for (i, key) in Self::alias_keys(fsrl).into_iter().enumerate() {
                let value = &self.records[idx].value;
                let bucket = self.values.entry(key).or_default();
                let unique = !bucket.iter().any(|&bi| &self.records[bi].value == value);
                if unique {
                    bucket.push(idx);
                }
                if i == 0 {
                    is_new_value = unique;
                }
            }
            if is_new_value {
                self.count += 1;
            }
        }

        fn clear_cache(&mut self) {
            self.values.clear();
            self.records.clear();
            self.count = 0;
        }

        fn get_count(&self) -> usize {
            self.count
        }
    }

    fn fsrl(fsrl_str: &str) -> Fsrl {
        Fsrl::from_string(fsrl_str).unwrap()
    }

    #[test]
    fn object_safety_via_boxed_dyn() {
        let provider: Box<dyn CachedPasswordProvider<MockProviders, MockSession>> =
            Box::new(MockCachedPasswordProvider::new());
        assert_eq!(provider.get_count(), 0);
    }

    #[test]
    fn added_password_is_retrievable_by_full_fsrl() {
        let mut provider = MockCachedPasswordProvider::new();
        let f = fsrl("file:///a.zip|zip:///secret.bin");
        let pw = Password::copy_of(&"hunter2".chars().collect::<Vec<_>>());

        provider.add_password(&f, &pw);

        let mut session = MockSession::new();
        let found: Vec<Password> =
            provider.get_passwords_for(&f, "unlock", &mut session).collect();
        assert_eq!(found, vec![pw]);
        assert_eq!(provider.get_count(), 1);
    }

    #[test]
    fn added_password_is_retrievable_by_plain_name_alone() {
        let mut provider = MockCachedPasswordProvider::new();
        let f = fsrl("file:///a.zip|zip:///secret.bin");
        let pw = Password::copy_of(&"hunter2".chars().collect::<Vec<_>>());
        provider.add_password(&f, &pw);

        // A lookup that only shares the plain filename should still find it, mirroring the
        // Java implementation's multi-alias indexing.
        let lookup_only_by_name =
            fsrl("file:///different/path.zip|zip:///secret.bin");
        let mut session = MockSession::new();
        let found: Vec<Password> = provider
            .get_passwords_for(&lookup_only_by_name, "unlock", &mut session)
            .collect();
        assert_eq!(found, vec![pw]);
    }

    #[test]
    fn added_password_is_retrievable_by_md5() {
        let mut provider = MockCachedPasswordProvider::new();
        let f = fsrl("file:///a.zip|zip:///secret.bin?MD5=deadbeef");
        let pw = Password::copy_of(&['x']);
        provider.add_password(&f, &pw);

        let lookup_by_md5 =
            fsrl("file:///other/path.zip|zip:///other.bin?MD5=deadbeef");
        let mut session = MockSession::new();
        let found: Vec<Password> =
            provider.get_passwords_for(&lookup_by_md5, "unlock", &mut session).collect();
        assert_eq!(found, vec![pw]);
    }

    #[test]
    fn duplicate_password_for_same_fsrl_does_not_increase_count() {
        let mut provider = MockCachedPasswordProvider::new();
        let f = fsrl("file:///a.zip|zip:///secret.bin");
        let pw = Password::copy_of(&['x']);

        provider.add_password(&f, &pw);
        provider.add_password(&f, &pw);

        assert_eq!(provider.get_count(), 1);
        let mut session = MockSession::new();
        let found: Vec<Password> =
            provider.get_passwords_for(&f, "unlock", &mut session).collect();
        assert_eq!(found, vec![pw]);
    }

    #[test]
    fn clear_cache_removes_everything() {
        let mut provider = MockCachedPasswordProvider::new();
        let f = fsrl("file:///a.zip|zip:///secret.bin");
        provider.add_password(&f, &Password::copy_of(&['x']));
        assert_eq!(provider.get_count(), 1);

        provider.clear_cache();

        assert_eq!(provider.get_count(), 0);
        let mut session = MockSession::new();
        let found: Vec<Password> =
            provider.get_passwords_for(&f, "unlock", &mut session).collect();
        assert!(found.is_empty());
    }

    #[test]
    fn lookup_for_unknown_fsrl_yields_empty_iterator() {
        let provider = MockCachedPasswordProvider::new();
        let f = fsrl("file:///never-added.bin");
        let mut session = MockSession::new();
        let found: Vec<Password> =
            provider.get_passwords_for(&f, "unlock", &mut session).collect();
        assert!(found.is_empty());
    }
}
