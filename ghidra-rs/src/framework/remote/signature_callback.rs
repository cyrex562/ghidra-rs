/// Provides a callback used to perform PKI authentication.
///
/// Instantiated by the server with a random token that the client must sign using a
/// certificate whose chain contains one of the `recognized_authorities`.  The callback
/// handler must invoke [`SignatureCallback::sign`] and return this object; authentication
/// fails if the signed response is not returned promptly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureCallback {
    recognized_authorities: Vec<String>,
    token: Vec<u8>,
    server_signature: Vec<u8>,
    signature: Option<Vec<u8>>,
    cert_chain: Option<Vec<Vec<u8>>>,
}

impl SignatureCallback {
    /// Construct a callback with a random token to be signed by the client.
    ///
    /// `recognized_authorities` contains X.500 distinguished names of approved CAs; one must
    /// appear in the signing certificate's chain.  `token` is the random bytes to sign.
    /// `server_signature` is the server's own signature of the token at generation time.
    pub fn new(
        recognized_authorities: Vec<String>,
        token: Vec<u8>,
        server_signature: Vec<u8>,
    ) -> Self {
        Self {
            recognized_authorities,
            token,
            server_signature,
            signature: None,
            cert_chain: None,
        }
    }

    /// Returns the list of approved certificate authority distinguished names.
    pub fn recognized_authorities(&self) -> &[String] {
        &self.recognized_authorities
    }

    /// Returns the token bytes to be signed by the user's certificate.
    pub fn token(&self) -> &[u8] {
        &self.token
    }

    /// Returns the server's signature of the token bytes.
    pub fn server_signature(&self) -> &[u8] {
        &self.server_signature
    }

    /// Returns the signed token bytes set by the callback handler, or `None` if not yet signed.
    pub fn signature(&self) -> Option<&[u8]> {
        self.signature.as_deref()
    }

    /// Returns the DER-encoded certificate chain used to sign the token, or `None` if not yet signed.
    pub fn certificate_chain(&self) -> Option<&[Vec<u8>]> {
        self.cert_chain.as_deref()
    }

    /// Set token signature data.  Must be invoked by the callback handler.
    ///
    /// `sig_cert_chain` is the DER-encoded certificate chain used to sign the token.
    /// `cert_signature` is the token signature produced by the client.
    pub fn sign(&mut self, sig_cert_chain: Vec<Vec<u8>>, cert_signature: Vec<u8>) {
        self.cert_chain = Some(sig_cert_chain);
        self.signature = Some(cert_signature);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_callback() -> SignatureCallback {
        SignatureCallback::new(
            vec!["CN=TestCA,O=Test,C=US".to_string()],
            vec![1, 2, 3, 4],
            vec![5, 6, 7, 8],
        )
    }

    #[test]
    fn test_new_fields() {
        let cb = make_callback();
        assert_eq!(cb.recognized_authorities(), &["CN=TestCA,O=Test,C=US"]);
        assert_eq!(cb.token(), &[1, 2, 3, 4]);
        assert_eq!(cb.server_signature(), &[5, 6, 7, 8]);
    }

    #[test]
    fn test_initial_signature_none() {
        let cb = make_callback();
        assert!(cb.signature().is_none());
    }

    #[test]
    fn test_initial_cert_chain_none() {
        let cb = make_callback();
        assert!(cb.certificate_chain().is_none());
    }

    #[test]
    fn test_sign_sets_signature_and_chain() {
        let mut cb = make_callback();
        let chain = vec![vec![0xaa, 0xbb], vec![0xcc, 0xdd]];
        let sig = vec![0x11, 0x22];
        cb.sign(chain.clone(), sig.clone());
        assert_eq!(cb.signature(), Some(sig.as_slice()));
        assert_eq!(cb.certificate_chain(), Some(chain.as_slice()));
    }

    #[test]
    fn test_sign_overwrites_previous() {
        let mut cb = make_callback();
        cb.sign(vec![vec![0x01]], vec![0x02]);
        cb.sign(vec![vec![0xaa]], vec![0xbb]);
        assert_eq!(cb.signature(), Some([0xbb].as_ref()));
        assert_eq!(cb.certificate_chain(), Some([vec![0xaa]].as_ref()));
    }

    #[test]
    fn test_multiple_recognized_authorities() {
        let cb = SignatureCallback::new(
            vec!["CN=CA1".to_string(), "CN=CA2".to_string()],
            vec![],
            vec![],
        );
        assert_eq!(cb.recognized_authorities().len(), 2);
    }

    #[test]
    fn test_empty_recognized_authorities() {
        let cb = SignatureCallback::new(vec![], vec![0x01], vec![0x02]);
        assert!(cb.recognized_authorities().is_empty());
    }

    #[test]
    fn test_clone_preserves_state() {
        let mut cb = make_callback();
        cb.sign(vec![vec![0x10]], vec![0x20]);
        let cb2 = cb.clone();
        assert_eq!(cb, cb2);
    }

    #[test]
    fn test_equality_unsigned() {
        let a = make_callback();
        let b = make_callback();
        assert_eq!(a, b);
    }

    #[test]
    fn test_inequality_after_sign() {
        let a = make_callback();
        let mut b = make_callback();
        b.sign(vec![], vec![0xff]);
        assert_ne!(a, b);
    }

    #[test]
    fn test_debug_contains_type_name() {
        let cb = make_callback();
        assert!(format!("{:?}", cb).contains("SignatureCallback"));
    }
}
