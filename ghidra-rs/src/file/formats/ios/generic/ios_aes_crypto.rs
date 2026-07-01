use std::io::{Cursor, Read};

use crate::util::exception::CryptoException;

/// Cipher algorithm name used by the Java source's `Cipher.getInstance` calls.
pub const CRYPTO_ALGORITHM: &str = "AES";

/// Cipher transformation string: AES in CBC mode with no padding.
pub const CRYPTO_TRANSFORMATION_CBC: &str = "AES/CBC/NoPadding";

const BLOCK_SIZE: usize = 16;

/// AES/CBC/NoPadding decryption helper used by iOS firmware image formats.
///
/// Port of `ghidra.file.formats.ios.generic.iOS_AesCrypto`. `encrypt()` and
/// `update()` are unimplemented in the Java source and remain unimplemented here.
pub struct IosAesCrypto {
    key_length: usize,
    key: Vec<u8>,
    iv: Vec<u8>,
}

impl IosAesCrypto {
    /// Creates a crypto helper from a raw AES key and initialization vector.
    ///
    /// # Panics
    /// Panics if `key` or `iv` is `None`, mirroring the Java constructor's
    /// `IllegalArgumentException` for a missing key or IV.
    pub fn new(key: Option<&[u8]>, iv: Option<&[u8]>) -> Self {
        let key = key
            .expect("KEY is not specified, check the XML file and verify the KEY is correct.");
        let iv =
            iv.expect("IV is not specified, check the XML file and verify the IV is correct.");
        Self { key_length: key.len() * 8, key: key.to_vec(), iv: iv.to_vec() }
    }

    /// Not implemented in the Java source; always returns an error.
    pub fn encrypt(&self, _plain_text: &[u8]) -> Result<Vec<u8>, CryptoException> {
        Err(CryptoException::new("encrypt() not implemented"))
    }

    /// Decrypts an AES/CBC/NoPadding-encrypted stream, mirroring `decrypt(InputStream)`.
    ///
    /// The Java source returns a lazily-decrypting `CipherInputStream`. This port has
    /// no caller that needs incremental decryption yet, so `input` is read to
    /// completion and decrypted eagerly, then handed back as a readable [`Cursor`].
    pub fn decrypt_stream<R: Read>(
        &self,
        mut input: R,
    ) -> Result<Cursor<Vec<u8>>, CryptoException> {
        let mut cipher_text = Vec::new();
        input.read_to_end(&mut cipher_text).map_err(CryptoException::from_cause)?;
        let plain_text = self.decrypt(&cipher_text)?;
        Ok(Cursor::new(plain_text))
    }

    /// Decrypts `cipher_text` using AES/CBC/NoPadding with the configured key and IV.
    pub fn decrypt(&self, cipher_text: &[u8]) -> Result<Vec<u8>, CryptoException> {
        let round_keys = key_expansion(&self.key).map_err(CryptoException::new)?;
        if cipher_text.len() % BLOCK_SIZE != 0 {
            return Err(CryptoException::new(format!(
                "Input length ({} bytes) is not a multiple of {} bytes",
                cipher_text.len(),
                BLOCK_SIZE
            )));
        }
        if self.iv.len() != BLOCK_SIZE {
            return Err(CryptoException::new(format!(
                "IV must be {} bytes, got {}",
                BLOCK_SIZE,
                self.iv.len()
            )));
        }

        let nr = round_keys.len() / 4 - 1;
        let mut plain_text = Vec::with_capacity(cipher_text.len());
        let mut prev_block = [0u8; BLOCK_SIZE];
        prev_block.copy_from_slice(&self.iv);

        for chunk in cipher_text.chunks(BLOCK_SIZE) {
            let mut block = [0u8; BLOCK_SIZE];
            block.copy_from_slice(chunk);
            let decrypted = inv_cipher(&block, &round_keys, nr);
            for i in 0..BLOCK_SIZE {
                plain_text.push(decrypted[i] ^ prev_block[i]);
            }
            prev_block = block;
        }

        Ok(plain_text)
    }

    /// Not implemented in the Java source; always returns an error.
    pub fn update(&self, _update: &[u8]) -> Result<(), CryptoException> {
        Err(CryptoException::new("update() not implemented"))
    }

    /// Returns the configured key length in bits.
    pub fn key_length(&self) -> usize {
        self.key_length
    }
}

// ---- AES core (FIPS-197). Decryption only: `encrypt()` is unimplemented, so no
// forward cipher is needed. ----

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

fn sub_word(w: [u8; 4]) -> [u8; 4] {
    [SBOX[w[0] as usize], SBOX[w[1] as usize], SBOX[w[2] as usize], SBOX[w[3] as usize]]
}

fn rot_word(w: [u8; 4]) -> [u8; 4] {
    [w[1], w[2], w[3], w[0]]
}

/// Expands `key` (16, 24, or 32 bytes) into the full AES round-key schedule.
fn key_expansion(key: &[u8]) -> Result<Vec<[u8; 4]>, String> {
    let nk = key.len() / 4;
    if key.len() % 4 != 0 || !matches!(nk, 4 | 6 | 8) {
        return Err(format!("Invalid AES key length: {} bits", key.len() * 8));
    }
    let nr = nk + 6;
    let total_words = 4 * (nr + 1);

    let mut w: Vec<[u8; 4]> = Vec::with_capacity(total_words);
    for i in 0..nk {
        w.push([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }
    for i in nk..total_words {
        let mut temp = w[i - 1];
        if i % nk == 0 {
            temp = sub_word(rot_word(temp));
            temp[0] ^= RCON[i / nk - 1];
        } else if nk > 6 && i % nk == 4 {
            temp = sub_word(temp);
        }
        let prev = w[i - nk];
        w.push([prev[0] ^ temp[0], prev[1] ^ temp[1], prev[2] ^ temp[2], prev[3] ^ temp[3]]);
    }
    Ok(w)
}

/// Multiplies `a` and `b` in GF(2^8) with the AES reduction polynomial (0x11B).
fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p: u8 = 0;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    p
}

fn add_round_key(state: &mut [[u8; 4]; 4], w: &[[u8; 4]], round: usize) {
    for c in 0..4 {
        let word = w[round * 4 + c];
        for r in 0..4 {
            state[r][c] ^= word[r];
        }
    }
}

fn inv_shift_rows(state: &mut [[u8; 4]; 4]) {
    for r in 1..4 {
        let row = state[r];
        for c in 0..4 {
            state[r][c] = row[(c + 4 - r) % 4];
        }
    }
}

fn inv_sub_bytes(state: &mut [[u8; 4]; 4]) {
    for row in state.iter_mut() {
        for b in row.iter_mut() {
            *b = INV_SBOX[*b as usize];
        }
    }
}

fn inv_mix_columns(state: &mut [[u8; 4]; 4]) {
    for c in 0..4 {
        let a0 = state[0][c];
        let a1 = state[1][c];
        let a2 = state[2][c];
        let a3 = state[3][c];
        state[0][c] = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9);
        state[1][c] = gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13);
        state[2][c] = gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11);
        state[3][c] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14);
    }
}

/// Decrypts a single 16-byte AES block (FIPS-197 `InvCipher`, straightforward form).
fn inv_cipher(input: &[u8; BLOCK_SIZE], w: &[[u8; 4]], nr: usize) -> [u8; BLOCK_SIZE] {
    let mut state = [[0u8; 4]; 4];
    for c in 0..4 {
        for r in 0..4 {
            state[r][c] = input[r + 4 * c];
        }
    }

    add_round_key(&mut state, w, nr);
    for round in (1..nr).rev() {
        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
        add_round_key(&mut state, w, round);
        inv_mix_columns(&mut state);
    }
    inv_shift_rows(&mut state);
    inv_sub_bytes(&mut state);
    add_round_key(&mut state, w, 0);

    let mut out = [0u8; BLOCK_SIZE];
    for c in 0..4 {
        for r in 0..4 {
            out[r + 4 * c] = state[r][c];
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Key material generated for this port and validated against `openssl enc` (not
    // reused Java test data, since the Java source has no unit tests of its own).
    const KEY128: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    const KEY192: [u8; 24] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    ];
    const KEY256: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const IV: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    const PT: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const CT128: [u8; 32] = [
        0x95, 0x4f, 0x64, 0xf2, 0xe4, 0xe8, 0x6e, 0x9e, 0xee, 0x82, 0xd2, 0x02, 0x16, 0x68, 0x48,
        0x99, 0xa9, 0x3b, 0x9d, 0xdb, 0x22, 0xe8, 0xab, 0x10, 0x4c, 0x61, 0xe7, 0x28, 0x83, 0x1d,
        0x6d, 0x5a,
    ];
    const CT192: [u8; 32] = [
        0x3f, 0xe7, 0x28, 0x6a, 0xbd, 0xe5, 0xf0, 0x39, 0x43, 0xd5, 0x77, 0x70, 0x20, 0x25, 0x96,
        0x26, 0xf7, 0xa4, 0x36, 0x26, 0x45, 0x51, 0x33, 0xf5, 0x06, 0x64, 0xfa, 0x76, 0x0a, 0xe3,
        0x69, 0x84,
    ];
    const CT256: [u8; 32] = [
        0x9f, 0x3b, 0x75, 0x04, 0x92, 0x6f, 0x8b, 0xd3, 0x6e, 0x31, 0x18, 0xe9, 0x03, 0xa4, 0xcd,
        0x4a, 0x25, 0xc1, 0x83, 0xf7, 0x0f, 0xdb, 0x48, 0x12, 0xcc, 0x24, 0x53, 0xfa, 0x00, 0xb3,
        0xd3, 0x90,
    ];

    #[test]
    fn constructor_computes_key_length_in_bits() {
        let crypto = IosAesCrypto::new(Some(&KEY128), Some(&IV));
        assert_eq!(crypto.key_length(), 128);
        let crypto = IosAesCrypto::new(Some(&KEY192), Some(&IV));
        assert_eq!(crypto.key_length(), 192);
        let crypto = IosAesCrypto::new(Some(&KEY256), Some(&IV));
        assert_eq!(crypto.key_length(), 256);
    }

    #[test]
    #[should_panic(expected = "KEY is not specified")]
    fn constructor_panics_on_missing_key() {
        IosAesCrypto::new(None, Some(&IV));
    }

    #[test]
    #[should_panic(expected = "IV is not specified")]
    fn constructor_panics_on_missing_iv() {
        IosAesCrypto::new(Some(&KEY128), None);
    }

    #[test]
    fn decrypt_aes128_cbc_matches_known_vector() {
        let crypto = IosAesCrypto::new(Some(&KEY128), Some(&IV));
        let plain = crypto.decrypt(&CT128).unwrap();
        assert_eq!(plain, PT.to_vec());
    }

    #[test]
    fn decrypt_aes192_cbc_matches_known_vector() {
        let crypto = IosAesCrypto::new(Some(&KEY192), Some(&IV));
        let plain = crypto.decrypt(&CT192).unwrap();
        assert_eq!(plain, PT.to_vec());
    }

    #[test]
    fn decrypt_aes256_cbc_matches_known_vector() {
        let crypto = IosAesCrypto::new(Some(&KEY256), Some(&IV));
        let plain = crypto.decrypt(&CT256).unwrap();
        assert_eq!(plain, PT.to_vec());
    }

    #[test]
    fn decrypt_empty_input_returns_empty_output() {
        let crypto = IosAesCrypto::new(Some(&KEY128), Some(&IV));
        assert_eq!(crypto.decrypt(&[]).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn decrypt_rejects_non_block_aligned_input() {
        let crypto = IosAesCrypto::new(Some(&KEY128), Some(&IV));
        let err = crypto.decrypt(&CT128[..20]).unwrap_err();
        assert!(err.to_string().contains("not a multiple of"));
    }

    #[test]
    fn decrypt_rejects_invalid_key_length() {
        let crypto = IosAesCrypto::new(Some(&[0u8; 20]), Some(&IV));
        let err = crypto.decrypt(&CT128).unwrap_err();
        assert!(err.to_string().contains("Invalid AES key length"));
    }

    #[test]
    fn decrypt_stream_reads_full_plaintext() {
        let crypto = IosAesCrypto::new(Some(&KEY128), Some(&IV));
        let mut stream = crypto.decrypt_stream(Cursor::new(CT128.to_vec())).unwrap();
        let mut out = Vec::new();
        stream.read_to_end(&mut out).unwrap();
        assert_eq!(out, PT.to_vec());
    }

    #[test]
    fn encrypt_is_not_implemented() {
        let crypto = IosAesCrypto::new(Some(&KEY128), Some(&IV));
        let err = crypto.encrypt(&PT).unwrap_err();
        assert_eq!(err.to_string(), "encrypt() not implemented");
    }

    #[test]
    fn update_is_not_implemented() {
        let crypto = IosAesCrypto::new(Some(&KEY128), Some(&IV));
        let err = crypto.update(&PT).unwrap_err();
        assert_eq!(err.to_string(), "update() not implemented");
    }

    #[test]
    fn cbc_chains_across_blocks_via_iv_and_prior_ciphertext() {
        // Repeat the same ciphertext block twice: block 2's plaintext must be XORed
        // against block 1's ciphertext (not the IV), proving CBC chaining is applied.
        let mut cipher_text = CT128.to_vec();
        cipher_text.extend_from_slice(&CT128[..BLOCK_SIZE]);

        let crypto = IosAesCrypto::new(Some(&KEY128), Some(&IV));
        let plain = crypto.decrypt(&cipher_text).unwrap();

        assert_eq!(&plain[..BLOCK_SIZE], &PT[..BLOCK_SIZE]);
        let mut expected_second_block = [0u8; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            expected_second_block[i] = PT[i] ^ CT128[i];
        }
        assert_eq!(&plain[BLOCK_SIZE..], &expected_second_block[..]);
    }
}
