use std::io;

use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
use crate::util::exception::{CancelledException, CryptoException};
use crate::util::task::TaskMonitor;

use super::decrypted_packet::DecryptedPacket;

/// Enum combining the three exceptions that decryption methods can throw.
///
/// Mirrors the checked exceptions declared on `Decryptor` methods:
/// `IOException`, `CryptoException`, and `CancelledException`.
#[derive(Debug)]
pub enum DecryptError {
    Io(io::Error),
    Crypto(CryptoException),
    Cancelled(CancelledException),
}

impl From<io::Error> for DecryptError {
    fn from(e: io::Error) -> Self {
        DecryptError::Io(e)
    }
}

impl From<CryptoException> for DecryptError {
    fn from(e: CryptoException) -> Self {
        DecryptError::Crypto(e)
    }
}

impl From<CancelledException> for DecryptError {
    fn from(e: CancelledException) -> Self {
        DecryptError::Cancelled(e)
    }
}

impl std::fmt::Display for DecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecryptError::Io(e) => write!(f, "IO error: {}", e),
            DecryptError::Crypto(e) => write!(f, "Crypto error: {}", e),
            DecryptError::Cancelled(e) => write!(f, "Cancelled: {}", e),
        }
    }
}

impl std::error::Error for DecryptError {}

/// Trait for decrypting encrypted byte sequences.
///
/// Port of `ghidra.file.crypto.Decryptor`. Implementations of this trait should
/// end in "Decryptor" (mirroring the Java class naming convention used for
/// extension discovery).
///
/// Decryptors are responsible for:
/// 1. Validating whether they can decrypt a given byte provider.
/// 2. Performing the actual decryption and returning the result.
pub trait Decryptor: Send + Sync {
    /// Determines whether this decryptor can decrypt the bytes in the provider.
    ///
    /// Mirrors `isValid(ByteProvider)` from the Java interface.
    ///
    /// # Arguments
    /// * `provider` - A mutable byte provider containing the bytes to validate.
    ///
    /// # Errors
    /// Returns an `io::Error` if the read operation fails.
    fn is_valid(&self, provider: &mut dyn ByteProvider) -> io::Result<bool>;

    /// Decrypts bytes from the provider and returns the decrypted packet.
    ///
    /// Mirrors `decrypt(String, String, ByteProvider, TaskMonitor)` from the Java interface.
    ///
    /// # Arguments
    /// * `firmware_name` - The name of the firmware being decrypted.
    /// * `firmware_path` - The path to the firmware file.
    /// * `provider` - A mutable byte provider containing the encrypted bytes.
    /// * `monitor` - A task monitor for progress tracking and cancellation.
    ///
    /// # Errors
    /// Returns a `DecryptError` if:
    /// * An I/O error occurs during reading (`DecryptError::Io`).
    /// * A cryptographic operation fails (`DecryptError::Crypto`).
    /// * The operation is cancelled (`DecryptError::Cancelled`).
    fn decrypt(
        &self,
        firmware_name: &str,
        firmware_path: &str,
        provider: &mut dyn ByteProvider,
        monitor: &dyn TaskMonitor,
    ) -> Result<DecryptedPacket, DecryptError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::io::Cursor;
    use std::path::PathBuf;

    struct MockByteProvider {
        data: Vec<u8>,
    }

    impl ByteProvider for MockByteProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.data.len() as u64)
        }

        fn is_valid_index(&mut self, index: u64) -> bool {
            index < self.data.len() as u64
        }

        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            if index < self.data.len() as u64 {
                Ok(self.data[index as usize])
            } else {
                Err(io::Error::new(io::ErrorKind::InvalidData, "index out of bounds"))
            }
        }

        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start.saturating_add(length);
            if end <= self.data.len() {
                Ok(self.data[start..end].to_vec())
            } else {
                Err(io::Error::new(io::ErrorKind::InvalidData, "index out of bounds"))
            }
        }

        fn write_byte(&mut self, index: u64, value: u8) -> io::Result<()> {
            if index < self.data.len() as u64 {
                self.data[index as usize] = value;
                Ok(())
            } else {
                Err(io::Error::new(io::ErrorKind::InvalidData, "index out of bounds"))
            }
        }

        fn write_bytes(&mut self, index: u64, values: &[u8]) -> io::Result<()> {
            let start = index as usize;
            let end = start.saturating_add(values.len());
            if end <= self.data.len() {
                self.data[start..end].copy_from_slice(values);
                Ok(())
            } else {
                Err(io::Error::new(io::ErrorKind::InvalidData, "index out of bounds"))
            }
        }
    }

    struct MockDecryptor {
        valid: bool,
    }

    impl Decryptor for MockDecryptor {
        fn is_valid(&self, _provider: &mut dyn ByteProvider) -> io::Result<bool> {
            Ok(self.valid)
        }

        fn decrypt(
            &self,
            _firmware_name: &str,
            _firmware_path: &str,
            _provider: &mut dyn ByteProvider,
            _monitor: &dyn TaskMonitor,
        ) -> Result<DecryptedPacket, DecryptError> {
            Ok(DecryptedPacket::from_file(PathBuf::from("/tmp/decrypted")))
        }
    }

    #[test]
    fn is_valid_returns_true() {
        let decryptor = MockDecryptor { valid: true };
        let mut provider = MockByteProvider { data: vec![0xDE, 0xAD, 0xBE, 0xEF] };
        assert!(decryptor.is_valid(&mut provider).unwrap());
    }

    #[test]
    fn is_valid_returns_false() {
        let decryptor = MockDecryptor { valid: false };
        let mut provider = MockByteProvider { data: vec![0xDE, 0xAD, 0xBE, 0xEF] };
        assert!(!decryptor.is_valid(&mut provider).unwrap());
    }

    #[test]
    fn decrypt_returns_file_packet() {
        let decryptor = MockDecryptor { valid: true };
        let mut provider = MockByteProvider { data: vec![0xDE, 0xAD, 0xBE, 0xEF] };
        let dummy_monitor = crate::util::task::DummyMonitor;

        let result = decryptor.decrypt("test_fw", "/path/to/fw", &mut provider, &dummy_monitor);
        assert!(result.is_ok());
        match result.unwrap() {
            DecryptedPacket::File(path) => assert_eq!(path, PathBuf::from("/tmp/decrypted")),
            DecryptedPacket::Stream { .. } => panic!("expected File variant"),
        }
    }

    #[test]
    fn decrypt_error_io_display() {
        let err = DecryptError::from(io::Error::new(io::ErrorKind::InvalidData, "read failed"));
        let msg = err.to_string();
        assert!(msg.contains("IO error"));
        assert!(msg.contains("read failed"));
    }

    #[test]
    fn decrypt_error_crypto_display() {
        let err = DecryptError::from(CryptoException::new("decrypt failed"));
        let msg = err.to_string();
        assert!(msg.contains("Crypto error"));
        assert!(msg.contains("decrypt failed"));
    }

    #[test]
    fn decrypt_error_cancelled_display() {
        let err = DecryptError::from(CancelledException::new("user stopped"));
        let msg = err.to_string();
        assert!(msg.contains("Cancelled"));
        assert!(msg.contains("user stopped"));
    }

    #[test]
    fn decrypt_error_is_std_error() {
        let err: Box<dyn std::error::Error> =
            Box::new(DecryptError::from(io::Error::new(io::ErrorKind::InvalidData, "test")));
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn mock_provider_read_bytes_validates_bounds() {
        let mut provider = MockByteProvider { data: vec![1, 2, 3, 4, 5] };
        let result = provider.read_bytes(2, 3);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![3, 4, 5]);
    }

    #[test]
    fn mock_provider_read_bytes_rejects_out_of_bounds() {
        let mut provider = MockByteProvider { data: vec![1, 2, 3] };
        let result = provider.read_bytes(2, 5);
        assert!(result.is_err());
    }

    #[test]
    fn mock_provider_write_bytes() {
        let mut provider = MockByteProvider { data: vec![1, 2, 3, 4, 5] };
        let result = provider.write_bytes(1, &[10, 20]);
        assert!(result.is_ok());
        assert_eq!(provider.data, vec![1, 10, 20, 4, 5]);
    }

    #[test]
    fn decryptor_is_send_and_sync() {
        // This test just verifies that Decryptor trait objects can be sent and synced.
        let decryptor: Box<dyn Decryptor> = Box::new(MockDecryptor { valid: true });
        fn assert_send_sync<T: Send + Sync>(_: &T) {}
        assert_send_sync(&decryptor);
    }
}
