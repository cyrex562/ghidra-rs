// Port of orig_src/Ghidra/Features/GhidraServer/src/main/java/ghidra/server/security/TokenGenerator.java
//
// Original license header (Apache-2.0, IP: GHIDRA):
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

use crate::generic::random::SecureRandomFactory;
use dashmap::DashMap;
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Max token time-to-live in milliseconds.
const MAX_TTL_MS: i64 = 60_000;

const TOKEN_SIZE: usize = 64;

/// Tracks timed token issuance and insures that tokens remain valid for
/// one-time consumption within a limited life-span.
struct CachedTokenSet {
    cache: DashMap<Vec<u8>, i64>,
}

impl CachedTokenSet {
    fn new() -> Arc<Self> {
        let set = Arc::new(CachedTokenSet { cache: DashMap::new() });
        let cleanup_set = Arc::clone(&set);
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(5));
            cleanup_set.cleanup();
        });
        set
    }

    fn add(&self, token: Vec<u8>) {
        self.cache.insert(token, current_time_millis());
    }

    /// Removes the token from the cache on retrieval and reports whether it
    /// was present and still within its time-to-live.
    fn consume(&self, token: &[u8]) -> bool {
        match self.cache.remove(token) {
            Some((_, stored_at)) => current_time_millis() - stored_at < MAX_TTL_MS,
            None => false,
        }
    }

    fn cleanup(&self) {
        let now = current_time_millis();
        self.cache.retain(|_, stored_at| now - *stored_at < MAX_TTL_MS);
    }
}

fn current_time_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before UNIX epoch")
        .as_millis() as i64
}

static TOKEN_CACHE: OnceLock<Arc<CachedTokenSet>> = OnceLock::new();

fn token_cache() -> &'static Arc<CachedTokenSet> {
    TOKEN_CACHE.get_or_init(CachedTokenSet::new)
}

fn get_long(data: &[u8], offset: usize) -> i64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&data[offset..offset + 8]);
    i64::from_be_bytes(bytes)
}

fn put_long(data: &mut [u8], offset: usize, v: i64) {
    data[offset..offset + 8].copy_from_slice(&v.to_be_bytes());
}

/// Generates and validates single-use, time-limited authentication tokens.
pub(crate) struct TokenGenerator;

impl TokenGenerator {
    /// Returns a single-use token byte sequence with embedded timestamp.
    pub(crate) fn get_new_token() -> Vec<u8> {
        let random = SecureRandomFactory::get_secure_random();
        let mut token = vec![0u8; TOKEN_SIZE - 8];
        random.fill_bytes(&mut token);

        let mut stamped_token = vec![0u8; TOKEN_SIZE];
        stamped_token[8..].copy_from_slice(&token);
        put_long(&mut stamped_token, 0, current_time_millis());

        token_cache().add(stamped_token.clone());
        stamped_token
    }

    /// Determines if the specified token has not yet been consumed and is
    /// still valid.
    ///
    /// NOTE: This method may only be invoked once per token, after which the
    /// token becomes invalid.
    pub(crate) fn is_valid_token(token: &[u8]) -> bool {
        if token.len() != TOKEN_SIZE || !token_cache().consume(token) {
            return false;
        }
        let issue_time = get_long(token, 0);
        if issue_time <= 0 {
            return false;
        }
        let diff = current_time_millis() - issue_time;
        diff >= 0 && diff < MAX_TTL_MS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_token_has_expected_size() {
        let token = TokenGenerator::get_new_token();
        assert_eq!(token.len(), TOKEN_SIZE);
    }

    #[test]
    fn test_new_token_is_valid_once() {
        let token = TokenGenerator::get_new_token();
        assert!(TokenGenerator::is_valid_token(&token));
    }

    #[test]
    fn test_token_is_single_use() {
        let token = TokenGenerator::get_new_token();
        assert!(TokenGenerator::is_valid_token(&token));
        // A second consumption attempt must fail: the token was removed from
        // the cache by the first successful validation.
        assert!(!TokenGenerator::is_valid_token(&token));
    }

    #[test]
    fn test_unknown_token_is_invalid() {
        let bogus = vec![0u8; TOKEN_SIZE];
        assert!(!TokenGenerator::is_valid_token(&bogus));
    }

    #[test]
    fn test_wrong_length_token_is_invalid() {
        let short = vec![0u8; TOKEN_SIZE - 1];
        assert!(!TokenGenerator::is_valid_token(&short));
    }

    #[test]
    fn test_expired_token_is_invalid() {
        let mut token = vec![0u8; TOKEN_SIZE];
        // Stamp the token with a timestamp far enough in the past to have
        // exceeded MAX_TTL_MS.
        put_long(&mut token, 0, current_time_millis() - MAX_TTL_MS - 1_000);
        token_cache().add(token.clone());
        assert!(!TokenGenerator::is_valid_token(&token));
    }

    #[test]
    fn test_future_timestamp_token_is_invalid() {
        let mut token = vec![0u8; TOKEN_SIZE];
        // A token stamped in the future (diff < 0) must never validate.
        put_long(&mut token, 0, current_time_millis() + MAX_TTL_MS);
        token_cache().add(token.clone());
        assert!(!TokenGenerator::is_valid_token(&token));
    }

    #[test]
    fn test_get_and_put_long_round_trip() {
        let mut data = vec![0u8; 8];
        put_long(&mut data, 0, 0x0102_0304_0506_0708_i64);
        assert_eq!(get_long(&data, 0), 0x0102_0304_0506_0708_i64);
    }

    #[test]
    fn test_generated_tokens_are_distinct() {
        let a = TokenGenerator::get_new_token();
        let b = TokenGenerator::get_new_token();
        assert_ne!(a, b);
    }
}
