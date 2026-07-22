use crate::filesystem::gfilesystem::crypto::crypto_provider::Session;
use crate::filesystem::gfilesystem::crypto::password_provider::PasswordProvider;
use crate::filesystem::seam_stubs::CachedFsrlLike;
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
pub trait CachedPasswordProvider<Fsrl: CachedFsrlLike, CP, S: Session<CP>>:
    PasswordProvider<Fsrl, CP, S>
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
    use crate::filesystem::seam_stubs::FsrlLike;
    use std::any::Any;
    use std::collections::{HashMap, HashSet};

    #[derive(Clone)]
    struct MockFsrl {
        full: String,
        pretty: String,
        name: String,
        md5: Option<String>,
    }
    impl FsrlLike for MockFsrl {}
    impl CachedFsrlLike for MockFsrl {
        fn fsrl_string(&self) -> String {
            self.full.clone()
        }
        fn fsrl_pretty_string(&self) -> String {
            self.pretty.clone()
        }
        fn fsrl_name(&self) -> String {
            self.name.clone()
        }
        fn fsrl_md5(&self) -> Option<String> {
            self.md5.clone()
        }
    }

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

        fn alias_keys(fsrl: &MockFsrl) -> Vec<String> {
            let mut keys = vec![fsrl.fsrl_string()];
            let pretty = fsrl.fsrl_pretty_string();
            if pretty != keys[0] {
                keys.push(pretty);
            }
            keys.push(fsrl.fsrl_name());
            if let Some(md5) = fsrl.fsrl_md5() {
                keys.push(md5);
            }
            keys
        }
    }

    impl PasswordProvider<MockFsrl, MockProviders, MockSession> for MockCachedPasswordProvider {
        fn get_passwords_for<'a>(
            &'a self,
            fsrl: &'a MockFsrl,
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

    impl CachedPasswordProvider<MockFsrl, MockProviders, MockSession> for MockCachedPasswordProvider {
        fn add_password(&mut self, fsrl: &MockFsrl, password: &Password) {
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

    fn fsrl(full: &str, pretty: &str, name: &str, md5: Option<&str>) -> MockFsrl {
        MockFsrl {
            full: full.to_string(),
            pretty: pretty.to_string(),
            name: name.to_string(),
            md5: md5.map(str::to_string),
        }
    }

    #[test]
    fn object_safety_via_boxed_dyn() {
        let provider: Box<dyn CachedPasswordProvider<MockFsrl, MockProviders, MockSession>> =
            Box::new(MockCachedPasswordProvider::new());
        assert_eq!(provider.get_count(), 0);
    }

    #[test]
    fn added_password_is_retrievable_by_full_fsrl() {
        let mut provider = MockCachedPasswordProvider::new();
        let f = fsrl("archive:/a.zip!secret.bin", "a.zip!secret.bin", "secret.bin", None);
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
        let f = fsrl("archive:/a.zip!secret.bin", "a.zip!secret.bin", "secret.bin", None);
        let pw = Password::copy_of(&"hunter2".chars().collect::<Vec<_>>());
        provider.add_password(&f, &pw);

        // A lookup that only shares the plain filename should still find it, mirroring the
        // Java implementation's multi-alias indexing.
        let lookup_only_by_name =
            fsrl("different:/path!secret.bin", "different/path!secret.bin", "secret.bin", None);
        let mut session = MockSession::new();
        let found: Vec<Password> = provider
            .get_passwords_for(&lookup_only_by_name, "unlock", &mut session)
            .collect();
        assert_eq!(found, vec![pw]);
    }

    #[test]
    fn added_password_is_retrievable_by_md5() {
        let mut provider = MockCachedPasswordProvider::new();
        let f = fsrl("archive:/a.zip!secret.bin", "a.zip!secret.bin", "secret.bin", Some("deadbeef"));
        let pw = Password::copy_of(&['x']);
        provider.add_password(&f, &pw);

        let lookup_by_md5 =
            fsrl("other:/path!other.bin", "other/path!other.bin", "other.bin", Some("deadbeef"));
        let mut session = MockSession::new();
        let found: Vec<Password> =
            provider.get_passwords_for(&lookup_by_md5, "unlock", &mut session).collect();
        assert_eq!(found, vec![pw]);
    }

    #[test]
    fn duplicate_password_for_same_fsrl_does_not_increase_count() {
        let mut provider = MockCachedPasswordProvider::new();
        let f = fsrl("archive:/a.zip!secret.bin", "a.zip!secret.bin", "secret.bin", None);
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
        let f = fsrl("archive:/a.zip!secret.bin", "a.zip!secret.bin", "secret.bin", None);
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
        let f = fsrl("archive:/never-added.bin", "never-added.bin", "never-added.bin", None);
        let mut session = MockSession::new();
        let found: Vec<Password> =
            provider.get_passwords_for(&f, "unlock", &mut session).collect();
        assert!(found.is_empty());
    }
}
