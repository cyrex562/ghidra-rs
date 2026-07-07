// Port of orig_src/Ghidra/Test/IntegrationTest/src/test.slow/java/ghidra/server/remote/SSHKeyUtil.java
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
//
//! SSH RSA key generation utilities for test purposes.
//!
//! The Java original manually DER-encodes a PKCS#1 RSA private key and emits it
//! inside a `-----BEGIN RSA PRIVATE KEY-----` PEM block, and hand-builds the
//! OpenSSH `ssh-rsa <base64> test` wire format for the public key.
//!
//! This Rust port reproduces the *observable outputs* faithfully:
//!   * index 0: the private key as a PKCS#1 PEM (`-----BEGIN RSA PRIVATE KEY-----`),
//!     which is exactly the PEM form the Java `getRSAPrivateKey` produces.
//!   * index 1: the OpenSSH public-key line `ssh-rsa <base64> test\n`, matching the
//!     Java `getRSAPublicKey` output (including the trailing `test` comment and newline).
//!
//! Deviation note: rather than re-implementing the manual ASN.1/SSH byte encoders,
//! the port delegates to the well-audited `rsa` (PKCS#1 PEM) and `ssh-key` (OpenSSH
//! public-key wire format) crates. The resulting strings are byte-for-byte
//! equivalent in structure to the Java output for any given key material.

use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
use rsa::RsaPrivateKey;
use ssh_key::public::RsaPublicKey as SshRsaPublicKey;
use ssh_key::PublicKey;

/// RSA key size (bits) used for generated test keys. The Java original uses 2048.
pub const RSA_KEY_BITS: usize = 2048;

/// Comment appended to the generated public key line (matches the Java `" test"`).
const PUBLIC_KEY_COMMENT: &str = "test";

/// Error type for SSH key generation.
#[derive(Debug)]
pub enum SshKeyError {
    /// RSA key generation or PKCS#1 PEM encoding failed.
    Rsa(rsa::Error),
    /// PKCS#1 PEM encoding failed.
    Pkcs1(rsa::pkcs1::Error),
    /// Conversion into the OpenSSH public-key representation failed.
    Ssh(ssh_key::Error),
}

impl std::fmt::Display for SshKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SshKeyError::Rsa(e) => write!(f, "RSA error: {e}"),
            SshKeyError::Pkcs1(e) => write!(f, "PKCS#1 error: {e}"),
            SshKeyError::Ssh(e) => write!(f, "SSH key error: {e}"),
        }
    }
}

impl std::error::Error for SshKeyError {}

impl From<rsa::Error> for SshKeyError {
    fn from(e: rsa::Error) -> Self {
        SshKeyError::Rsa(e)
    }
}

impl From<rsa::pkcs1::Error> for SshKeyError {
    fn from(e: rsa::pkcs1::Error) -> Self {
        SshKeyError::Pkcs1(e)
    }
}

impl From<ssh_key::Error> for SshKeyError {
    fn from(e: ssh_key::Error) -> Self {
        SshKeyError::Ssh(e)
    }
}

/// Generate an RSA key pair and return `[private_pem, public_ssh]`.
///
/// Port of `SSHKeyUtil.generateSSHRSAKeys()`.
///
/// * `[0]` is the private key as a PKCS#1 PEM file
///   (`-----BEGIN RSA PRIVATE KEY-----` ... `-----END RSA PRIVATE KEY-----`).
/// * `[1]` is the SSH public-key file content in OpenSSH `authorized_keys`
///   format: `ssh-rsa <base64> test\n`.
///
/// Keys are randomly generated, so callers must not rely on exact bytes.
pub fn generate_ssh_rsa_keys() -> Result<[String; 2], SshKeyError> {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, RSA_KEY_BITS)?;

    let private_pem = get_rsa_private_key(&private_key)?;
    let public_ssh = get_rsa_public_key(&private_key)?;

    Ok([private_pem, public_ssh])
}

/// Format the RSA private key as a PKCS#1 PEM string.
///
/// Port of `SSHKeyUtil.getRSAPrivateKey(KeyPair)`. The Java code hand-encodes the
/// PKCS#1 `RSAPrivateKey` ASN.1 structure and wraps it in the
/// `-----BEGIN RSA PRIVATE KEY-----` PEM armor; `to_pkcs1_pem` produces the
/// identical PEM form (LF line endings, matching the Java `'\n'` separators).
fn get_rsa_private_key(private_key: &RsaPrivateKey) -> Result<String, SshKeyError> {
    let pem = private_key.to_pkcs1_pem(LineEnding::LF)?;
    Ok(pem.to_string())
}

/// Format the RSA public key as an OpenSSH public-key line.
///
/// Port of `SSHKeyUtil.getRSAPublicKey(KeyPair)`. Produces `ssh-rsa <base64> test\n`.
fn get_rsa_public_key(private_key: &RsaPrivateKey) -> Result<String, SshKeyError> {
    let rsa_public = private_key.to_public_key();
    let ssh_rsa = SshRsaPublicKey::try_from(&rsa_public)?;
    let mut public_key = PublicKey::from(ssh_rsa);
    public_key.set_comment(PUBLIC_KEY_COMMENT);
    // to_openssh() emits `ssh-rsa <base64> test`; Java appends a trailing newline.
    Ok(format!("{}\n", public_key.to_openssh()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::traits::PublicKeyParts;
    use ssh_key::PublicKey;

    #[test]
    fn test_generate_ssh_rsa_keys_public_format() {
        let [_private_pem, public_ssh] = generate_ssh_rsa_keys().expect("key generation");
        assert!(
            public_ssh.starts_with("ssh-rsa "),
            "public key must start with 'ssh-rsa ', got: {public_ssh:?}"
        );
        assert!(
            public_ssh.ends_with(" test\n"),
            "public key must end with ' test\\n', got: {public_ssh:?}"
        );
    }

    #[test]
    fn test_public_key_round_trips_via_openssh() {
        let [_private_pem, public_ssh] = generate_ssh_rsa_keys().expect("key generation");
        // Parses back as a valid OpenSSH public key (trim trailing newline).
        let parsed = PublicKey::from_openssh(public_ssh.trim_end())
            .expect("public key should parse via from_openssh");
        assert_eq!(parsed.comment(), "test");
        assert!(
            parsed.key_data().rsa().is_some(),
            "parsed key should be RSA"
        );
    }

    #[test]
    fn test_private_pem_format_and_round_trip() {
        let [private_pem, _public_ssh] = generate_ssh_rsa_keys().expect("key generation");
        assert!(
            private_pem.starts_with("-----BEGIN RSA PRIVATE KEY-----"),
            "private key must be PKCS#1 PEM, got start: {:?}",
            &private_pem[..private_pem.len().min(40)]
        );
        assert!(
            private_pem.contains("-----END RSA PRIVATE KEY-----"),
            "private key must contain PKCS#1 PEM end marker"
        );

        // Round-trip the PKCS#1 PEM back into an RSA private key.
        use rsa::pkcs1::DecodeRsaPrivateKey;
        let parsed = RsaPrivateKey::from_pkcs1_pem(&private_pem)
            .expect("private key should parse via from_pkcs1_pem");
        assert_eq!(parsed.to_public_key().size() * 8, RSA_KEY_BITS);
    }

    #[test]
    fn test_public_matches_private_and_is_expected_bit_size() {
        let [private_pem, public_ssh] = generate_ssh_rsa_keys().expect("key generation");

        use rsa::pkcs1::DecodeRsaPrivateKey;
        let priv_key = RsaPrivateKey::from_pkcs1_pem(&private_pem).expect("parse private");
        let priv_public = priv_key.to_public_key();

        let parsed_pub =
            PublicKey::from_openssh(public_ssh.trim_end()).expect("parse public");
        let ssh_rsa = parsed_pub.key_data().rsa().expect("rsa public key");
        let rsa_from_ssh: rsa::RsaPublicKey =
            ssh_rsa.try_into().expect("convert ssh rsa -> rsa");

        // The public key derived from the SSH line must match the one in the PEM.
        assert_eq!(rsa_from_ssh, priv_public);
        // And it must be the expected bit size.
        assert_eq!(rsa_from_ssh.size() * 8, RSA_KEY_BITS);
    }
}
