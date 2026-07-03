//! SSH authentication callback.
//!
//! Port of `ghidra.framework.remote.SSHSignatureCallback`.

use dsa::signature::hazmat::PrehashSigner as _;
use dsa::signature::SignatureEncoding as _;
use sha1::{Digest, Sha1};
use ssh_key::PrivateKey;

/// Errors produced while signing an [`SshSignatureCallback`].
#[derive(Debug)]
pub enum SshSignError {
    /// The supplied private key uses an algorithm other than RSA or DSA.
    UnsupportedKey,
    /// Signature generation failed.
    SignatureFailed(String),
}

impl std::fmt::Display for SshSignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SshSignError::UnsupportedKey => write!(f, "Unsupported SSH private key"),
            SshSignError::SignatureFailed(msg) => {
                write!(f, "Cannot generate SSH signature: {msg}")
            }
        }
    }
}

impl std::error::Error for SshSignError {}

/// Callback used to perform SSH authentication.
///
/// Instantiated by the server with a random `token` which must be signed using the user's SSH
/// private key.  It is the responsibility of the callback handler to invoke [`SshSignatureCallback::sign`]
/// and return this object in response to the callback.  The callback must be signed and returned
/// to the server promptly or authentication will fail.
///
/// The supplied token is validated by the server during authentication as one it had issued, but
/// is primarily intended as the basis for the client's signature.
///
/// # Signature format
///
/// The Java original uses BouncyCastle's `RSADigestSigner`/`DSADigestSigner` over a `SHA1Digest`
/// and wraps the raw signature bytes in the SSH wire format:
/// `writeString(alg) || writeBlock(rawSignature)`, where a "block" is a big-endian `u32` length
/// prefix followed by the bytes.  This port reproduces that wire framing exactly.
///
/// * For RSA the raw signature is a PKCS#1 v1.5 signature of the SHA-1 digest of the token, which
///   is bit-for-bit identical to BouncyCastle's `RSADigestSigner(SHA1Digest)` output.
/// * For DSA the raw signature is the ASN.1 DER encoding of the `(r, s)` pair over the SHA-1
///   digest, matching BouncyCastle's `DSADigestSigner(DSASigner, SHA1Digest)` default encoding.
///
/// DSA signatures are randomized, so their exact bytes are not reproducible across runs, but they
/// verify against the corresponding public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshSignatureCallback {
    token: Vec<u8>,
    server_signature: Vec<u8>,
    signature: Option<Vec<u8>>,
}

impl SshSignatureCallback {
    /// Construct a callback with a random `token` to be signed by the client.
    ///
    /// `server_signature` is the server's signature of the token (using server PKI).
    pub fn new(token: Vec<u8>, server_signature: Vec<u8>) -> Self {
        Self {
            token,
            server_signature,
            signature: None,
        }
    }

    /// Returns the token to be signed using the user's certificate.
    pub fn token(&self) -> &[u8] {
        &self.token
    }

    /// Returns the signed token bytes set by the callback handler, or `None` if not yet signed.
    pub fn signature(&self) -> Option<&[u8]> {
        self.signature.as_deref()
    }

    /// Returns the server's signature of the token bytes (using server PKI).
    pub fn server_signature(&self) -> &[u8] {
        &self.server_signature
    }

    /// Returns `true` if this callback has been signed.
    pub fn is_signed(&self) -> bool {
        self.signature.is_some()
    }

    /// Sign this challenge with the specified SSH private key.
    ///
    /// Dispatches on the key algorithm (RSA or DSA), signs the SHA-1 digest of the token, and
    /// stores the SSH-wire-formatted signature retrievable via [`Self::signature`].
    ///
    /// Returns [`SshSignError::UnsupportedKey`] for algorithms other than RSA/DSA and
    /// [`SshSignError::SignatureFailed`] if signature generation fails.
    pub fn sign(&mut self, private_key: &PrivateKey) -> Result<(), SshSignError> {
        match private_key.key_data() {
            ssh_key::private::KeypairData::Rsa(rsa_keypair) => {
                let mut priv_key = rsa_private_key_from_keypair(rsa_keypair)?;
                // The key is reconstructed from components without CRT precomputation;
                // signing requires the precomputed CRT values.
                priv_key
                    .precompute()
                    .map_err(|e| SshSignError::SignatureFailed(e.to_string()))?;
                // PKCS#1 v1.5 over a SHA-1 digest of the token; identical to
                // BouncyCastle RSADigestSigner(SHA1Digest).
                let digest = Sha1::digest(&self.token);
                let raw = priv_key
                    .sign(rsa::Pkcs1v15Sign::new::<Sha1>(), &digest)
                    .map_err(|e| SshSignError::SignatureFailed(e.to_string()))?;
                self.signature = Some(build_ssh_signature("ssh-rsa", &raw));
                Ok(())
            }
            ssh_key::private::KeypairData::Dsa(dsa_keypair) => {
                let priv_key = dsa::SigningKey::try_from(dsa_keypair)
                    .map_err(|e| SshSignError::SignatureFailed(e.to_string()))?;
                let digest = Sha1::digest(&self.token);
                let sig: dsa::Signature = priv_key
                    .sign_prehash(&digest)
                    .map_err(|e| SshSignError::SignatureFailed(e.to_string()))?;
                // ASN.1 DER encoding of (r, s); matches BouncyCastle DSADigestSigner default.
                let raw = sig.to_bytes();
                self.signature = Some(build_ssh_signature("ssh-dss", &raw));
                Ok(())
            }
            _ => Err(SshSignError::UnsupportedKey),
        }
    }
}

/// Encode `algorithm` and `raw_signature` in the SSH wire format used by the Java original:
/// `writeString(algorithm) || writeBlock(raw_signature)`, each element being a big-endian `u32`
/// length prefix followed by its bytes.
fn build_ssh_signature(algorithm: &str, raw_signature: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    ssh_write_block(algorithm.as_bytes(), &mut out);
    ssh_write_block(raw_signature, &mut out);
    out
}

/// Write a big-endian `u32` length prefix followed by `value`.
fn ssh_write_block(value: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

/// Reconstruct an [`rsa::RsaPrivateKey`] from the OpenSSH RSA keypair components.
///
/// This deliberately does not use ssh-key 0.6.7's `TryFrom<&RsaKeypair> for RsaPrivateKey`,
/// which contains a bug: it passes the first prime `p` twice to `from_components` instead of
/// `p` and `q`, yielding an invalid key that fails validation. Here we build the key from the
/// modulus, exponents, and both primes directly.
fn rsa_private_key_from_keypair(
    keypair: &ssh_key::private::RsaKeypair,
) -> Result<rsa::RsaPrivateKey, SshSignError> {
    let err = |e: ssh_key::Error| SshSignError::SignatureFailed(e.to_string());
    let n = rsa::BigUint::try_from(&keypair.public.n).map_err(err)?;
    let e = rsa::BigUint::try_from(&keypair.public.e).map_err(err)?;
    let d = rsa::BigUint::try_from(&keypair.private.d).map_err(err)?;
    let p = rsa::BigUint::try_from(&keypair.private.p).map_err(err)?;
    let q = rsa::BigUint::try_from(&keypair.private.q).map_err(err)?;
    rsa::RsaPrivateKey::from_components(n, e, d, vec![p, q])
        .map_err(|e| SshSignError::SignatureFailed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::RsaPublicKey;

    const TOKEN: &[u8] = b"the-random-challenge-token";

    // Build a deterministic RSA key at test time from a fixed-seed RNG, so signing is reproducible.
    // Produces a valid RsaPrivateKey and its OpenSSH-wrapped PrivateKey. Test-only.
    fn test_rsa_private_key() -> (rsa::RsaPrivateKey, PrivateKey) {
        use rsa::traits::PublicKeyParts;
        // Deterministic RNG seeded with a fixed value.
        let mut rng = DeterministicRng::new(0x5eed_1234_abcd_0001);
        let bits = 2048;
        let mut rsa_priv = rsa::RsaPrivateKey::new(&mut rng, bits).expect("rsa keygen");
        assert_eq!(rsa_priv.size() * 8, bits);
        // Populate CRT values so the key can be re-encoded into OpenSSH keypair form
        // (which requires the CRT coefficient).
        rsa_priv.precompute().expect("precompute");
        let keypair = ssh_key::private::RsaKeypair::try_from(&rsa_priv).expect("ssh rsa keypair");
        let ssh_priv = PrivateKey::new(
            ssh_key::private::KeypairData::Rsa(keypair),
            "test-rsa-key",
        )
        .expect("ssh private key");
        (rsa_priv, ssh_priv)
    }

    /// Minimal deterministic RNG (SplitMix64) for reproducible key generation in tests.
    struct DeterministicRng {
        state: u64,
    }

    impl DeterministicRng {
        fn new(seed: u64) -> Self {
            Self { state: seed }
        }
        fn next_u64(&mut self) -> u64 {
            self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
    }

    impl rsa::rand_core::RngCore for DeterministicRng {
        fn next_u32(&mut self) -> u32 {
            (self.next_u64() >> 32) as u32
        }
        fn next_u64(&mut self) -> u64 {
            DeterministicRng::next_u64(self)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let mut i = 0;
            while i < dest.len() {
                let bytes = self.next_u64().to_le_bytes();
                let take = core::cmp::min(8, dest.len() - i);
                dest[i..i + take].copy_from_slice(&bytes[..take]);
                i += take;
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl rsa::rand_core::CryptoRng for DeterministicRng {}

    /// Parse the SSH-wire signature back into (algorithm, raw_signature).
    fn parse_ssh_signature(sig: &[u8]) -> (String, Vec<u8>) {
        fn read_block<'a>(buf: &'a [u8]) -> (&'a [u8], &'a [u8]) {
            let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
            let rest = &buf[4..];
            (&rest[..len], &rest[len..])
        }
        let (alg, rest) = read_block(sig);
        let (raw, tail) = read_block(rest);
        assert!(tail.is_empty(), "trailing bytes in ssh signature");
        (String::from_utf8(alg.to_vec()).unwrap(), raw.to_vec())
    }

    #[test]
    fn test_getters_before_sign() {
        let cb = SshSignatureCallback::new(vec![1, 2, 3], vec![9, 8, 7]);
        assert_eq!(cb.token(), &[1, 2, 3]);
        assert_eq!(cb.server_signature(), &[9, 8, 7]);
        assert!(cb.signature().is_none());
        assert!(!cb.is_signed());
    }

    #[test]
    fn test_sign_sets_signature_and_is_signed() {
        let (_pub, ssh_priv) = test_rsa_private_key();
        let mut cb = SshSignatureCallback::new(TOKEN.to_vec(), vec![0xaa]);
        assert!(!cb.is_signed());
        cb.sign(&ssh_priv).expect("sign");
        assert!(cb.is_signed());
        assert!(cb.signature().is_some());
        // Token and server signature are unchanged by signing.
        assert_eq!(cb.token(), TOKEN);
        assert_eq!(cb.server_signature(), &[0xaa]);
    }

    #[test]
    fn test_signature_wire_format_algorithm() {
        let (_priv, ssh_priv) = test_rsa_private_key();
        let mut cb = SshSignatureCallback::new(TOKEN.to_vec(), vec![]);
        cb.sign(&ssh_priv).expect("sign");
        let (alg, _raw) = parse_ssh_signature(cb.signature().unwrap());
        assert_eq!(alg, "ssh-rsa");
    }

    #[test]
    fn test_signature_verifies_against_public_key() {
        let (rsa_priv, ssh_priv) = test_rsa_private_key();
        let mut cb = SshSignatureCallback::new(TOKEN.to_vec(), vec![]);
        cb.sign(&ssh_priv).expect("sign");

        let (_alg, raw) = parse_ssh_signature(cb.signature().unwrap());

        // Verify the raw PKCS#1 v1.5 signature over SHA-1(token) using the public key.
        let pub_key = RsaPublicKey::from(&rsa_priv);
        let digest = Sha1::digest(TOKEN);
        pub_key
            .verify(rsa::Pkcs1v15Sign::new::<Sha1>(), &digest, &raw)
            .expect("signature should verify against derived public key");
    }

    #[test]
    fn test_sign_is_deterministic_for_rsa() {
        let (_p, ssh_priv) = test_rsa_private_key();
        let mut a = SshSignatureCallback::new(TOKEN.to_vec(), vec![]);
        let mut b = SshSignatureCallback::new(TOKEN.to_vec(), vec![]);
        a.sign(&ssh_priv).unwrap();
        b.sign(&ssh_priv).unwrap();
        // RSA PKCS#1 v1.5 is deterministic, so identical tokens yield identical signatures.
        assert_eq!(a.signature(), b.signature());
    }

    #[test]
    fn test_wrong_token_fails_verification() {
        let (rsa_priv, ssh_priv) = test_rsa_private_key();
        let mut cb = SshSignatureCallback::new(TOKEN.to_vec(), vec![]);
        cb.sign(&ssh_priv).expect("sign");
        let (_alg, raw) = parse_ssh_signature(cb.signature().unwrap());

        let pub_key = RsaPublicKey::from(&rsa_priv);
        let bad_digest = Sha1::digest(b"a-different-token");
        assert!(pub_key
            .verify(rsa::Pkcs1v15Sign::new::<Sha1>(), &bad_digest, &raw)
            .is_err());
    }

    #[test]
    fn test_build_ssh_signature_layout() {
        // "abc" (3 bytes) then raw [0xde,0xad] (2 bytes).
        let out = build_ssh_signature("abc", &[0xde, 0xad]);
        assert_eq!(
            out,
            vec![0, 0, 0, 3, b'a', b'b', b'c', 0, 0, 0, 2, 0xde, 0xad]
        );
    }

    #[test]
    fn test_clone_and_eq() {
        let (_p, ssh_priv) = test_rsa_private_key();
        let mut cb = SshSignatureCallback::new(TOKEN.to_vec(), vec![1]);
        cb.sign(&ssh_priv).unwrap();
        let cb2 = cb.clone();
        assert_eq!(cb, cb2);
        let unsigned = SshSignatureCallback::new(TOKEN.to_vec(), vec![1]);
        assert_ne!(cb, unsigned);
    }
}
