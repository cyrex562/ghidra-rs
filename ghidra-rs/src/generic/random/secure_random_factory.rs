use rand::rngs::OsRng;
use rand::RngCore;
use std::sync::{Mutex, OnceLock};

static INSTANCE: OnceLock<SecureRandom> = OnceLock::new();

/// A thread-safe, cryptographically secure random number generator.
///
/// This wraps `rand::rngs::OsRng` in a singleton pattern matching Java's
/// `SecureRandom` behavior from the original `generic.random.SecureRandomFactory`.
pub struct SecureRandom {
    generator: Mutex<OsRng>,
}

impl SecureRandom {
    /// Generates the next random 32-bit unsigned integer.
    pub fn gen_u32(&self) -> u32 {
        let mut rng = self.generator.lock().unwrap();
        rng.next_u32()
    }

    /// Generates the next random 64-bit unsigned integer.
    pub fn gen_u64(&self) -> u64 {
        let mut rng = self.generator.lock().unwrap();
        rng.next_u64()
    }

    /// Fills the given buffer with random bytes.
    pub fn fill_bytes(&self, dest: &mut [u8]) {
        let mut rng = self.generator.lock().unwrap();
        rng.fill_bytes(dest);
    }
}

/// Factory for acquiring a thread-safe, cryptographically secure random number generator.
///
/// Port of `generic.random.SecureRandomFactory` from Ghidra.
/// Provides a singleton instance of `SecureRandom` that initializes on first use,
/// attempting to use OS-provided entropy sources for cryptographic strength.
pub struct SecureRandomFactory;

impl SecureRandomFactory {
    /// Returns a reference to the singleton secure random number generator.
    ///
    /// This method initializes the generator on first use using the OS entropy source.
    /// Subsequent calls return the same cached instance.
    pub fn get_secure_random() -> &'static SecureRandom {
        INSTANCE.get_or_init(|| {
            crate::util::msg::Msg::info(
                "SecureRandomFactory",
                &"Initializing Random Number Generator...",
            );
            let instance = SecureRandom {
                generator: Mutex::new(OsRng),
            };
            crate::util::msg::Msg::info(
                "SecureRandomFactory",
                &"Random Number Generator initialization complete: OS entropy",
            );
            instance
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_secure_random_returns_singleton() {
        let rng1 = SecureRandomFactory::get_secure_random();
        let rng2 = SecureRandomFactory::get_secure_random();
        assert_eq!(rng1 as *const _, rng2 as *const _);
    }

    #[test]
    fn test_gen_u32_produces_values() {
        let rng = SecureRandomFactory::get_secure_random();
        let val1 = rng.gen_u32();
        let val2 = rng.gen_u32();
        // Should produce u32 values (can't really test randomness, but ensure they're generated)
        let _ = val1;
        let _ = val2;
    }

    #[test]
    fn test_gen_u64_produces_values() {
        let rng = SecureRandomFactory::get_secure_random();
        let val1 = rng.gen_u64();
        let val2 = rng.gen_u64();
        // Should produce u64 values
        let _ = val1;
        let _ = val2;
    }

    #[test]
    fn test_fill_bytes_fills_buffer() {
        let rng = SecureRandomFactory::get_secure_random();
        let mut buf = [0u8; 16];
        rng.fill_bytes(&mut buf);
        // Buffer should be filled with some value (not all zeros from randomness perspective)
        // We just verify the method works without panicking
        let sum: u32 = buf.iter().map(|&b| b as u32).sum();
        let _ = sum;
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let rng = Arc::new(());
        let mut handles = vec![];

        for _ in 0..10 {
            let rng_clone = Arc::clone(&rng);
            let handle = thread::spawn(move || {
                let secure_rng = SecureRandomFactory::get_secure_random();
                let _val = secure_rng.gen_u32();
                let mut buf = [0u8; 8];
                secure_rng.fill_bytes(&mut buf);
                drop(rng_clone);
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }
}
