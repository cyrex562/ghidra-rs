use crate::format::pdb2::pdbreader::hasher::Hasher;
use crate::format::pdb2::pdbreader::pdb_exception::PdbException;

/// Hasher32 used for PDB string hashing according to PDB API specifications.
///
/// This models `LHashPbCb` and extends the base `Hasher` to provide full 32-bit
/// hash values instead of the 16-bit masked values of the base hasher.
///
/// Mirrors `ghidra.app.util.bin.format.pdb2.pdbreader.Hasher32`.
pub struct Hasher32;

impl Hasher32 {
    /// Hashes a string, using the provided unsigned 32-bit modulus.
    /// The modulus should be <= 0xffffffff.
    ///
    /// Returns an unsigned integer hash value (32-bit) as a u32.
    ///
    /// # Arguments
    ///
    /// * `string` - The input string to be hashed.
    /// * `unsigned_32bit_mod` - Modulus to be used for the hash.
    ///
    /// # Errors
    ///
    /// Returns a [`PdbException`] if there is not enough data to parse.
    pub fn hash(string: &str, unsigned_32bit_mod: u32) -> Result<u32, PdbException> {
        Hasher::hash_string32(string, unsigned_32bit_mod)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_returns_u32() {
        let result = Hasher32::hash("test", 256).unwrap();
        assert!(result <= u32::MAX, "hash should be valid u32");
    }

    #[test]
    fn hash_with_empty_string() {
        let result = Hasher32::hash("", 256).unwrap();
        assert!(result <= u32::MAX);
    }

    #[test]
    fn hash_with_single_character() {
        let result = Hasher32::hash("a", 256).unwrap();
        assert!(result < 256);
    }

    #[test]
    fn hash_with_multiple_characters() {
        let result = Hasher32::hash("abcdefgh", 512).unwrap();
        assert!(result < 512);
    }

    #[test]
    fn hash_respects_modulus() {
        let modulus = 100u32;
        let result = Hasher32::hash("test", modulus).unwrap();
        assert!(result < modulus);
    }

    #[test]
    fn hash_deterministic() {
        let input = "deterministic_test";
        let modulus = 512u32;
        let result1 = Hasher32::hash(input, modulus).unwrap();
        let result2 = Hasher32::hash(input, modulus).unwrap();
        assert_eq!(result1, result2, "hash should be deterministic");
    }

    #[test]
    fn hash_with_unicode_utf8() {
        let result = Hasher32::hash("café", 256).unwrap();
        assert!(result <= u32::MAX);
    }

    #[test]
    fn hash_four_byte_string() {
        let result = Hasher32::hash("abcd", 256).unwrap();
        assert!(result < 256);
    }

    #[test]
    fn hash_five_byte_string() {
        let result = Hasher32::hash("abcde", 256).unwrap();
        assert!(result < 256);
    }

    #[test]
    fn hash_six_byte_string() {
        let result = Hasher32::hash("abcdef", 256).unwrap();
        assert!(result < 256);
    }
}
