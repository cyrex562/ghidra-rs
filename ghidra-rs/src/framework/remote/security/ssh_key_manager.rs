//! SSH private/public key loading and decryption.
//!
//! Port of `ghidra.framework.remote.security.SSHKeyManager`.
//!
//! The Java original delegates PEM parsing and decryption to BouncyCastle. This port
//! reproduces the same behavior against the traditional OpenSSL PEM format
//! (`-----BEGIN RSA PRIVATE KEY-----` / `-----BEGIN DSA PRIVATE KEY-----`, optionally
//! encrypted via a `Proc-Type: 4,ENCRYPTED` / `DEK-Info: <cipher>,<iv>` header pair) using
//! the `rsa`/`dsa`/`ssh-key`/`aes` crates plus the already-ported [`MD5DigestChecksumAlgorithm`]
//! for the OpenSSL `EVP_BytesToKey` key derivation. Only the modern `AES-{128,192,256}-CBC`
//! ciphers are supported for encrypted keys (BouncyCastle also supports the legacy
//! `DES-CBC`/`DES-EDE3-CBC` ciphers, which this port does not reproduce).

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;
use std::sync::Mutex;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, KeyInit};
use dsa::{BigUint as DsaBigUint, Components as DsaComponents, SigningKey as DsaSigningKey};
use rsa::pkcs1::DecodeRsaPrivateKey;
use ssh_key::private::{DsaKeypair, KeypairData, RsaKeypair};
use ssh_key::public::KeyData;
use ssh_key::{PrivateKey, PublicKey};

use crate::app::plugin::core::checksums::md5_digest_checksum_algorithm::MD5DigestChecksumAlgorithm;
use crate::framework::key_store_password_provider::KeyStorePasswordProvider;
use crate::util::msg::Msg;

static PASSWORD_PROVIDER: Mutex<Option<Box<dyn KeyStorePasswordProvider + Send>>> = Mutex::new(None);

/// Errors produced while loading or decrypting an SSH key.
#[derive(Debug)]
pub enum SshKeyManagerError {
    /// The requested key file does not exist.
    FileNotFound(String),
    /// Underlying I/O failure while reading the key.
    Io(io::Error),
    /// The key text is not a well-formed (or supported) SSH private/public key.
    InvalidKey(String),
    /// The key uses a PEM/cipher format this port does not implement.
    UnsupportedFormat(String),
    /// The key is encrypted but no password (or no password provider) was available.
    PasswordRequired,
    /// Failure constructing/decoding the `ssh-key` crate representation.
    Ssh(ssh_key::Error),
}

impl std::fmt::Display for SshKeyManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SshKeyManagerError::FileNotFound(path) => {
                write!(f, "SSH private key file not found: {path}")
            }
            SshKeyManagerError::Io(e) => write!(f, "{e}"),
            SshKeyManagerError::InvalidKey(msg) => write!(f, "{msg}"),
            SshKeyManagerError::UnsupportedFormat(msg) => write!(f, "{msg}"),
            SshKeyManagerError::PasswordRequired => {
                write!(f, "Password required to open SSH private keystore")
            }
            SshKeyManagerError::Ssh(e) => write!(f, "SSH key error: {e}"),
        }
    }
}

impl std::error::Error for SshKeyManagerError {}

impl From<io::Error> for SshKeyManagerError {
    fn from(e: io::Error) -> Self {
        SshKeyManagerError::Io(e)
    }
}

/// Set the password provider used to decrypt PKI-protected (encrypted) SSH private keys.
///
/// Port of `SSHKeyManager.setProtectedKeyStorePasswordProvider`.
pub fn set_protected_key_store_password_provider(provider: Box<dyn KeyStorePasswordProvider + Send>) {
    *PASSWORD_PROVIDER.lock().unwrap() = Some(provider);
}

/// Return the SSH private key corresponding to the specified key file.
///
/// If the key file is encrypted, the currently installed password provider is used to
/// obtain the decryption password.
///
/// Port of `SSHKeyManager.getSSHPrivateKey(File)`.
pub fn get_ssh_private_key_from_file(ssh_private_key_file: &Path) -> Result<PrivateKey, SshKeyManagerError> {
    if !ssh_private_key_file.is_file() {
        return Err(SshKeyManagerError::FileNotFound(
            ssh_private_key_file.display().to_string(),
        ));
    }
    let file = File::open(ssh_private_key_file)?;
    get_ssh_private_key(file, &ssh_private_key_file.display().to_string())
}

/// Return the SSH private key read from the specified reader.
///
/// If the key is encrypted, the currently installed password provider is used to obtain
/// the decryption password.
///
/// Port of `SSHKeyManager.getSSHPrivateKey(InputStream)`.
pub fn get_ssh_private_key_from_reader<R: Read>(
    ssh_private_key_in: R,
) -> Result<PrivateKey, SshKeyManagerError> {
    get_ssh_private_key(ssh_private_key_in, "Protected SSH Key")
}

/// Which legacy OpenSSL PEM private key format the `-----BEGIN ...-----` marker names.
enum KeyKind {
    Rsa,
    Dsa,
}

fn get_ssh_private_key<R: Read>(reader: R, src_name: &str) -> Result<PrivateKey, SshKeyManagerError> {
    let mut lines = BufReader::new(reader).lines();

    let first_line = match lines.next() {
        Some(line) => line?,
        None => return Err(SshKeyManagerError::InvalidKey("Invalid SSH Private Key".to_string())),
    };
    if !first_line.starts_with("-----BEGIN ") || !first_line.contains(" KEY-----") {
        return Err(SshKeyManagerError::InvalidKey("Invalid SSH Private Key".to_string()));
    }
    let key_kind = if first_line.starts_with("-----BEGIN RSA PRIVATE KEY-----") {
        KeyKind::Rsa
    } else if first_line.starts_with("-----BEGIN DSA PRIVATE KEY-----") {
        KeyKind::Dsa
    } else {
        Msg::error("SSHKeyManager", &"Unsupported SSH Key Format (see svrREADME.html)");
        return Err(SshKeyManagerError::UnsupportedFormat(
            "Unsupported SSH Private Key".to_string(),
        ));
    };

    let mut headers: Vec<(String, String)> = Vec::new();
    let mut body = String::new();
    let mut past_headers = false;
    for line in lines {
        let line = line?;
        if line.starts_with("-----END ") {
            break;
        }
        if !past_headers {
            if line.is_empty() {
                past_headers = true;
                continue;
            }
            if let Some(idx) = line.find(':') {
                let key = line[..idx].trim().to_string();
                let value = line[idx + 1..].trim().to_string();
                headers.push((key, value));
                continue;
            }
            past_headers = true;
        }
        body.push_str(line.trim());
    }

    let raw = decode_base64(&body)?;

    let dek_info = headers
        .iter()
        .find(|(key, _)| key == "DEK-Info")
        .map(|(_, value)| value.clone());

    let der = match dek_info {
        Some(dek_info) => decrypt_legacy_pem_body(&raw, &dek_info, src_name)?,
        None => raw,
    };

    match key_kind {
        KeyKind::Rsa => {
            let rsa_priv = rsa::RsaPrivateKey::from_pkcs1_der(&der)
                .map_err(|e| SshKeyManagerError::InvalidKey(format!("Invalid RSA private key: {e}")))?;
            let keypair = RsaKeypair::try_from(&rsa_priv).map_err(SshKeyManagerError::Ssh)?;
            PrivateKey::new(KeypairData::Rsa(keypair), "").map_err(SshKeyManagerError::Ssh)
        }
        KeyKind::Dsa => {
            let signing_key = parse_legacy_dsa_der(&der)?;
            let keypair = DsaKeypair::try_from(&signing_key)
                .map_err(|e| SshKeyManagerError::InvalidKey(format!("Invalid DSA private key: {e}")))?;
            PrivateKey::new(KeypairData::Dsa(keypair), "").map_err(SshKeyManagerError::Ssh)
        }
    }
}

/// Decrypt a legacy OpenSSL PEM body given its `DEK-Info` header value (`<cipher>,<iv-hex>`).
fn decrypt_legacy_pem_body(
    ciphertext: &[u8],
    dek_info: &str,
    src_name: &str,
) -> Result<Vec<u8>, SshKeyManagerError> {
    let (algorithm, iv_hex) = dek_info
        .split_once(',')
        .ok_or_else(|| SshKeyManagerError::InvalidKey("Malformed DEK-Info header".to_string()))?;

    let key_len = match algorithm {
        "AES-128-CBC" => 16,
        "AES-192-CBC" => 24,
        "AES-256-CBC" => 32,
        other => {
            return Err(SshKeyManagerError::UnsupportedFormat(format!(
                "Unsupported SSH private key cipher: {other}"
            )))
        }
    };

    let iv = decode_hex(iv_hex)?;
    if iv.len() != 16 {
        return Err(SshKeyManagerError::UnsupportedFormat(format!(
            "Unsupported SSH private key cipher IV size: {}",
            iv.len()
        )));
    }
    let mut iv_arr = [0u8; 16];
    iv_arr.copy_from_slice(&iv);

    let mut password_chars = {
        let guard = PASSWORD_PROVIDER.lock().unwrap();
        let provider = guard.as_ref().ok_or(SshKeyManagerError::PasswordRequired)?;
        provider
            .get_key_store_password(src_name, false)
            .ok_or(SshKeyManagerError::PasswordRequired)?
    };
    let mut password_bytes: Vec<u8> = password_chars.iter().collect::<String>().into_bytes();

    let key = evp_bytes_to_key(&password_bytes, &iv_arr[..8], key_len);

    // Zero the password material now that the derived key no longer needs it.
    for c in password_chars.iter_mut() {
        *c = '\0';
    }
    password_bytes.iter_mut().for_each(|b| *b = 0);

    aes_cbc_decrypt(&key, iv_arr, ciphertext)
}

/// OpenSSL's `EVP_BytesToKey` key derivation (MD5, single iteration) used by traditional
/// encrypted PEM files.
fn evp_bytes_to_key(password: &[u8], salt: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len);
    let mut prev_digest: Vec<u8> = Vec::new();
    while key.len() < key_len {
        let mut input = Vec::with_capacity(prev_digest.len() + password.len() + salt.len());
        input.extend_from_slice(&prev_digest);
        input.extend_from_slice(password);
        input.extend_from_slice(salt);

        let mut md5 = MD5DigestChecksumAlgorithm::new();
        md5.update_checksum(&input);
        let digest = *md5.checksum().unwrap();

        key.extend_from_slice(&digest);
        prev_digest = digest.to_vec();
    }
    key.truncate(key_len);
    key
}

fn aes_cbc_decrypt(key: &[u8], iv: [u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>, SshKeyManagerError> {
    match key.len() {
        16 => {
            let cipher = aes::Aes128::new_from_slice(key)
                .map_err(|_| SshKeyManagerError::InvalidKey("Invalid AES key".to_string()))?;
            aes_cbc_decrypt_with(&cipher, iv, ciphertext)
        }
        24 => {
            let cipher = aes::Aes192::new_from_slice(key)
                .map_err(|_| SshKeyManagerError::InvalidKey("Invalid AES key".to_string()))?;
            aes_cbc_decrypt_with(&cipher, iv, ciphertext)
        }
        32 => {
            let cipher = aes::Aes256::new_from_slice(key)
                .map_err(|_| SshKeyManagerError::InvalidKey("Invalid AES key".to_string()))?;
            aes_cbc_decrypt_with(&cipher, iv, ciphertext)
        }
        other => Err(SshKeyManagerError::UnsupportedFormat(format!(
            "Unsupported AES key size: {} bits",
            other * 8
        ))),
    }
}

fn aes_cbc_decrypt_with<C: BlockDecrypt>(
    cipher: &C,
    iv: [u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<u8>, SshKeyManagerError> {
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return Err(SshKeyManagerError::InvalidKey(
            "Corrupt encrypted SSH private key".to_string(),
        ));
    }

    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut prev_block = iv;
    for chunk in ciphertext.chunks_exact(16) {
        let mut block = GenericArray::from_slice(chunk).clone();
        cipher.decrypt_block(&mut block);
        for i in 0..16 {
            block[i] ^= prev_block[i];
        }
        plaintext.extend_from_slice(block.as_slice());
        prev_block.copy_from_slice(chunk);
    }

    let pad = *plaintext
        .last()
        .ok_or_else(|| SshKeyManagerError::InvalidKey("Corrupt encrypted SSH private key".to_string()))?
        as usize;
    if pad == 0 || pad > 16 || pad > plaintext.len() {
        return Err(SshKeyManagerError::InvalidKey(
            "Corrupt encrypted SSH private key (bad padding); incorrect password?".to_string(),
        ));
    }
    plaintext.truncate(plaintext.len() - pad);
    Ok(plaintext)
}

/// Parse the traditional (non-PKCS#8) OpenSSL DSA private key ASN.1 structure:
/// `SEQUENCE { version INTEGER, p INTEGER, q INTEGER, g INTEGER, y INTEGER, x INTEGER }`.
fn parse_legacy_dsa_der(der: &[u8]) -> Result<DsaSigningKey, SshKeyManagerError> {
    let mut pos = 0usize;
    let tag = *der.get(pos).ok_or_else(invalid_dsa_der)?;
    if tag != 0x30 {
        return Err(invalid_dsa_der());
    }
    pos += 1;
    let seq_len = read_der_length(der, &mut pos)?;
    let seq_end = pos.checked_add(seq_len).ok_or_else(invalid_dsa_der)?;
    if seq_end != der.len() {
        return Err(invalid_dsa_der());
    }

    let _version = read_der_integer(der, &mut pos)?;
    let p = read_der_integer(der, &mut pos)?;
    let q = read_der_integer(der, &mut pos)?;
    let g = read_der_integer(der, &mut pos)?;
    let y = read_der_integer(der, &mut pos)?;
    let x = read_der_integer(der, &mut pos)?;
    if pos != seq_end {
        return Err(invalid_dsa_der());
    }

    let components = DsaComponents::from_components(
        DsaBigUint::from_bytes_be(p),
        DsaBigUint::from_bytes_be(q),
        DsaBigUint::from_bytes_be(g),
    )
    .map_err(|e| SshKeyManagerError::InvalidKey(format!("Invalid DSA private key: {e}")))?;
    let verifying_key = dsa::VerifyingKey::from_components(components, DsaBigUint::from_bytes_be(y))
        .map_err(|e| SshKeyManagerError::InvalidKey(format!("Invalid DSA private key: {e}")))?;
    DsaSigningKey::from_components(verifying_key, DsaBigUint::from_bytes_be(x))
        .map_err(|e| SshKeyManagerError::InvalidKey(format!("Invalid DSA private key: {e}")))
}

fn invalid_dsa_der() -> SshKeyManagerError {
    SshKeyManagerError::InvalidKey("Invalid DSA private key encoding".to_string())
}

fn read_der_length(data: &[u8], pos: &mut usize) -> Result<usize, SshKeyManagerError> {
    let first = *data.get(*pos).ok_or_else(invalid_dsa_der)?;
    *pos += 1;
    if first & 0x80 == 0 {
        Ok(first as usize)
    } else {
        let num_bytes = (first & 0x7f) as usize;
        if num_bytes == 0 || num_bytes > std::mem::size_of::<usize>() {
            return Err(invalid_dsa_der());
        }
        let mut len = 0usize;
        for _ in 0..num_bytes {
            let b = *data.get(*pos).ok_or_else(invalid_dsa_der)?;
            *pos += 1;
            len = (len << 8) | b as usize;
        }
        Ok(len)
    }
}

fn read_der_integer<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a [u8], SshKeyManagerError> {
    let tag = *data.get(*pos).ok_or_else(invalid_dsa_der)?;
    if tag != 0x02 {
        return Err(invalid_dsa_der());
    }
    *pos += 1;
    let len = read_der_length(data, pos)?;
    let start = *pos;
    let end = start.checked_add(len).ok_or_else(invalid_dsa_der)?;
    let bytes = data.get(start..end).ok_or_else(invalid_dsa_der)?;
    *pos = end;
    Ok(bytes)
}

/// Attempt to instantiate an SSH public key from the specified file, which contains a
/// single public key.
///
/// Port of `SSHKeyManager.getSSHPublicKey(File)`.
pub fn get_ssh_public_key(ssh_public_key_file: &Path) -> Result<KeyData, SshKeyManagerError> {
    let file = File::open(ssh_public_key_file)?;
    let reader = BufReader::new(file);

    let mut key_line: Option<String> = None;
    for line in reader.lines() {
        let line = line?;
        if !line.starts_with("ssh-") {
            continue;
        }
        key_line = Some(line);
        break;
    }

    if let Some(line) = key_line {
        let mut parts = line.split_whitespace();
        if let (Some(algorithm), Some(base64_key)) = (parts.next(), parts.next()) {
            if algorithm.starts_with("ssh-") {
                let pubkey_bytes = decode_base64(base64_key)?;
                let public_key = PublicKey::from_bytes(&pubkey_bytes).map_err(SshKeyManagerError::Ssh)?;
                return Ok(public_key.key_data().clone());
            }
        }
    }

    Err(SshKeyManagerError::InvalidKey(format!(
        "Invalid SSH public key file, supported SSH public key not found: {}",
        ssh_public_key_file.display()
    )))
}

/// Decode a standard (RFC 4648) Base64 string, ignoring embedded whitespace.
fn decode_base64(input: &str) -> Result<Vec<u8>, SshKeyManagerError> {
    fn value(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let mut out = Vec::with_capacity(input.len() * 3 / 4 + 3);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for b in input.bytes() {
        if b.is_ascii_whitespace() || b == b'=' {
            continue;
        }
        let v = value(b)
            .ok_or_else(|| SshKeyManagerError::InvalidKey("Invalid base64 in SSH key".to_string()))?;
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Ok(out)
}

/// Decode a hex string (as used by the `DEK-Info` PEM header) into bytes.
fn decode_hex(input: &str) -> Result<Vec<u8>, SshKeyManagerError> {
    fn nibble(b: u8) -> Result<u8, SshKeyManagerError> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err(SshKeyManagerError::InvalidKey("Invalid hex in DEK-Info header".to_string())),
        }
    }

    let bytes = input.trim().as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(SshKeyManagerError::InvalidKey(
            "Invalid hex in DEK-Info header".to_string(),
        ));
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks(2) {
        out.push((nibble(chunk[0])? << 4) | nibble(chunk[1])?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::traits::PublicKeyParts;
    use std::cell::RefCell;
    use std::io::Cursor;

    struct StaticPasswordProvider {
        password: RefCell<Option<Vec<char>>>,
    }

    impl KeyStorePasswordProvider for StaticPasswordProvider {
        fn get_key_store_password(&self, _keystore_path: &str, _password_error: bool) -> Option<Vec<char>> {
            self.password.borrow().clone()
        }
    }

    fn install_password(password: Option<&str>) {
        let provider = StaticPasswordProvider {
            password: RefCell::new(password.map(|p| p.chars().collect())),
        };
        set_protected_key_store_password_provider(Box::new(provider));
    }

    fn generate_unencrypted_rsa_pem() -> String {
        let mut rng = rand::thread_rng();
        let private_key = rsa::RsaPrivateKey::new(&mut rng, 512).expect("rsa keygen");
        private_key
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .expect("pkcs1 pem")
            .to_string()
    }

    #[test]
    fn test_decode_base64_round_trips_known_bytes() {
        // "hello" -> "aGVsbG8="
        let decoded = decode_base64("aGVsbG8=").unwrap();
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn test_decode_base64_ignores_whitespace() {
        let decoded = decode_base64("aG Vs\nbG8=").unwrap();
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn test_decode_base64_rejects_invalid_char() {
        assert!(decode_base64("!!!!").is_err());
    }

    #[test]
    fn test_decode_hex_round_trips() {
        assert_eq!(decode_hex("00ff10").unwrap(), vec![0x00, 0xff, 0x10]);
        assert_eq!(decode_hex("DEADBEEF").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_decode_hex_rejects_odd_length() {
        assert!(decode_hex("abc").is_err());
    }

    #[test]
    fn test_evp_bytes_to_key_is_deterministic_and_sized() {
        let key1 = evp_bytes_to_key(b"password", &[1, 2, 3, 4, 5, 6, 7, 8], 32);
        let key2 = evp_bytes_to_key(b"password", &[1, 2, 3, 4, 5, 6, 7, 8], 32);
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_evp_bytes_to_key_differs_by_password() {
        let key1 = evp_bytes_to_key(b"password1", &[0u8; 8], 16);
        let key2 = evp_bytes_to_key(b"password2", &[0u8; 8], 16);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_get_ssh_private_key_from_reader_rejects_non_pem_content() {
        let err = get_ssh_private_key_from_reader(Cursor::new(b"not a key".to_vec())).unwrap_err();
        assert!(matches!(err, SshKeyManagerError::InvalidKey(_)));
    }

    #[test]
    fn test_get_ssh_private_key_from_reader_rejects_unsupported_key_type() {
        let pem = "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n";
        let err = get_ssh_private_key_from_reader(Cursor::new(pem.as_bytes().to_vec())).unwrap_err();
        assert!(matches!(err, SshKeyManagerError::UnsupportedFormat(_)));
    }

    #[test]
    fn test_get_ssh_private_key_from_file_missing_file() {
        let path = Path::new("/nonexistent/path/to/key.pem");
        let err = get_ssh_private_key_from_file(path).unwrap_err();
        assert!(matches!(err, SshKeyManagerError::FileNotFound(_)));
    }

    #[test]
    fn test_get_ssh_private_key_from_reader_parses_unencrypted_rsa_key() {
        let pem = generate_unencrypted_rsa_pem();
        let private_key =
            get_ssh_private_key_from_reader(Cursor::new(pem.into_bytes())).expect("parse rsa key");
        assert!(private_key.key_data().rsa().is_some());
    }

    #[test]
    fn test_get_ssh_private_key_from_reader_parsed_rsa_key_matches_source() {
        let mut rng = rand::thread_rng();
        let private_key = rsa::RsaPrivateKey::new(&mut rng, 512).expect("rsa keygen");
        let pem = private_key
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .expect("pkcs1 pem")
            .to_string();

        let parsed = get_ssh_private_key_from_reader(Cursor::new(pem.into_bytes())).expect("parse rsa key");
        let rsa_data = parsed.key_data().rsa().expect("rsa key data");
        let n: rsa::BigUint = (&rsa_data.public.n).try_into().expect("n mpint");
        assert_eq!(n, private_key.to_public_key().n().clone());
    }

    #[test]
    fn test_get_ssh_public_key_parses_generated_openssh_line() {
        let mut rng = rand::thread_rng();
        let private_key = rsa::RsaPrivateKey::new(&mut rng, 512).expect("rsa keygen");
        let ssh_public: ssh_key::public::RsaPublicKey =
            (&private_key.to_public_key()).try_into().expect("ssh rsa public key");
        let public_key = ssh_key::PublicKey::from(ssh_public);
        let openssh_line = format!("{} comment\n", public_key.to_openssh().expect("to_openssh"));

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("id_rsa.pub");
        std::fs::write(&path, openssh_line).expect("write pub key file");

        let key_data = get_ssh_public_key(&path).expect("parse public key");
        assert!(key_data.rsa().is_some());
    }

    #[test]
    fn test_get_ssh_public_key_rejects_file_without_ssh_line() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("not_a_key.pub");
        std::fs::write(&path, "just some text\n").expect("write file");

        let err = get_ssh_public_key(&path).unwrap_err();
        assert!(matches!(err, SshKeyManagerError::InvalidKey(_)));
    }

    #[test]
    fn test_get_ssh_private_key_from_reader_returns_password_required_when_encrypted_and_no_provider() {
        // A syntactically valid encrypted RSA PEM (contents need not decrypt to a real key
        // for this test since PasswordRequired should be returned before decryption).
        let pem = "-----BEGIN RSA PRIVATE KEY-----\n\
Proc-Type: 4,ENCRYPTED\n\
DEK-Info: AES-128-CBC,00000000000000000000000000000000\n\
\n\
AAAA\n\
-----END RSA PRIVATE KEY-----\n";
        let err = get_ssh_private_key_from_reader(Cursor::new(pem.as_bytes().to_vec())).unwrap_err();
        assert!(matches!(err, SshKeyManagerError::PasswordRequired));
    }

    #[test]
    fn test_password_provider_round_trip_via_set_protected_key_store_password_provider() {
        install_password(Some("hunter42"));
        let guard = PASSWORD_PROVIDER.lock().unwrap();
        let provider = guard.as_ref().expect("provider installed");
        let password = provider.get_key_store_password("test", false).expect("password");
        assert_eq!(password.iter().collect::<String>(), "hunter42");
    }
}
