/// Result of signing a token byte array with a certificate.
///
/// Bundles the original token, the signature over it, the algorithm used,
/// and the DER-encoded certificate chain whose private key produced the signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedToken {
    /// Original token byte array.
    pub token: Vec<u8>,
    /// Signature over the token bytes.
    pub signature: Vec<u8>,
    /// Signing algorithm name (e.g. `"SHA256withRSA"`).
    pub algorithm: String,
    /// DER-encoded certificate chain whose leaf key produced `signature`.
    pub cert_chain: Vec<Vec<u8>>,
}

impl SignedToken {
    pub(crate) fn new(
        token: Vec<u8>,
        signature: Vec<u8>,
        cert_chain: Vec<Vec<u8>>,
        algorithm: String,
    ) -> Self {
        Self {
            token,
            signature,
            cert_chain,
            algorithm,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_token() -> SignedToken {
        SignedToken::new(
            vec![1, 2, 3],
            vec![4, 5, 6],
            vec![vec![0xaa, 0xbb], vec![0xcc, 0xdd]],
            "SHA256withRSA".to_string(),
        )
    }

    #[test]
    fn test_fields_round_trip() {
        let st = make_token();
        assert_eq!(st.token, vec![1, 2, 3]);
        assert_eq!(st.signature, vec![4, 5, 6]);
        assert_eq!(st.algorithm, "SHA256withRSA");
        assert_eq!(st.cert_chain, vec![vec![0xaa, 0xbb], vec![0xcc, 0xdd]]);
    }

    #[test]
    fn test_clone_equals_original() {
        let st = make_token();
        assert_eq!(st.clone(), st);
    }

    #[test]
    fn test_inequality_different_token() {
        let a = make_token();
        let b = SignedToken::new(vec![9, 9], vec![4, 5, 6], vec![], "SHA256withRSA".to_string());
        assert_ne!(a, b);
    }

    #[test]
    fn test_inequality_different_algorithm() {
        let a = make_token();
        let b = SignedToken::new(vec![1, 2, 3], vec![4, 5, 6], vec![], "SHA1withRSA".to_string());
        assert_ne!(a, b);
    }

    #[test]
    fn test_empty_cert_chain() {
        let st = SignedToken::new(vec![], vec![], vec![], String::new());
        assert!(st.cert_chain.is_empty());
    }

    #[test]
    fn test_debug_contains_type_name() {
        let st = make_token();
        assert!(format!("{:?}", st).contains("SignedToken"));
    }
}
