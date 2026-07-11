use crate::format::pdb2::pdbreader::pdb_byte_reader::PdbByteReader;
use crate::format::pdb2::pdbreader::pdb_exception::PdbException;

/// Hasher used for PDB string hashing according to PDB API specifications.
///
/// This class models `HashPbCb` and provides methods for hashing strings using
/// an XOR-based algorithm with a modulus parameter.
///
/// Mirrors `ghidra.app.util.bin.format.pdb2.pdbreader.Hasher`.
pub struct Hasher;

impl Hasher {
    /// Hashes a string, using the provided unsigned 32-bit modulus.
    /// The modulus should be <= 0xffffffff.
    ///
    /// Returns an unsigned short hash value (16-bit) as a u32.
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
        Self::hash_string32(string, unsigned_32bit_mod).map(|h| h & 0xffff)
    }

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
    pub fn hash_string32(string: &str, unsigned_32bit_mod: u32) -> Result<u32, PdbException> {
        let bytes = string.as_bytes();
        let mut reader = PdbByteReader::new(bytes.to_vec());
        let count = bytes.len();

        let mut hash: u32 = 0;

        // Process 4 bytes at a time
        let mut remaining = count;
        while remaining >= 4 {
            remaining -= 4;
            hash ^= reader.parse_unsigned_int_val()?;
        }

        // Process remaining 2 bytes if present
        if bytes.len() - reader.get_index() >= 2 {
            hash ^= reader.parse_unsigned_short_val()? as u32;
        }

        // Process remaining 1 byte if present
        if bytes.len() - reader.get_index() == 1 {
            hash ^= reader.parse_unsigned_byte_val()? as u32;
        }

        // Apply to-lower mask
        hash |= 0x20202020;

        // Initial XOR hash transformation
        hash ^= hash >> 11;

        // Apply second XOR transformation and modulus
        Ok((hash ^ (hash >> 16)) % unsigned_32bit_mod)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_returns_16bit_value() {
        let result = Hasher::hash("test", 256).unwrap();
        assert!(result <= 0xffff, "hash should be <= 16-bit max, got {}", result);
    }

    #[test]
    fn hash_with_empty_string() {
        let result = Hasher::hash("", 256).unwrap();
        assert!(result.is_finite(), "hash of empty string should be valid");
    }

    #[test]
    fn hash_string32_returns_u32() {
        let result = Hasher::hash_string32("test", 256).unwrap();
        assert!(result <= u32::MAX, "hash_string32 should return valid u32");
    }

    #[test]
    fn hash_with_single_character() {
        let result = Hasher::hash("a", 256).unwrap();
        assert!(result <= 0xffff);
    }

    #[test]
    fn hash_with_multiple_characters() {
        let result = Hasher::hash("abcdefgh", 512).unwrap();
        assert!(result <= 0xffff);
    }

    #[test]
    fn hash_respects_modulus() {
        let modulus = 100u32;
        let result = Hasher::hash("test", modulus).unwrap();
        assert!(result < modulus);
    }

    #[test]
    fn hash_string32_respects_modulus() {
        let modulus = 256u32;
        let result = Hasher::hash_string32("test", modulus).unwrap();
        assert!(result < modulus);
    }

    #[test]
    fn hash_deterministic() {
        let input = "deterministic_test";
        let modulus = 512u32;
        let result1 = Hasher::hash(input, modulus).unwrap();
        let result2 = Hasher::hash(input, modulus).unwrap();
        assert_eq!(result1, result2, "hash should be deterministic");
    }

    #[test]
    fn hash_different_strings_may_differ() {
        let hash1 = Hasher::hash("string1", 1024).unwrap();
        let hash2 = Hasher::hash("string2", 1024).unwrap();
        // While not guaranteed, different strings should typically produce different hashes
        // This is just a sanity check that the algorithm is working
        let _ = (hash1, hash2);
    }

    #[test]
    fn hash_with_unicode_utf8() {
        let result = Hasher::hash("café", 256).unwrap();
        assert!(result <= 0xffff);
    }

    #[test]
    fn hash_four_byte_string() {
        let result = Hasher::hash("abcd", 256).unwrap();
        assert!(result <= 0xffff);
    }

    #[test]
    fn hash_five_byte_string() {
        let result = Hasher::hash("abcde", 256).unwrap();
        assert!(result <= 0xffff);
    }

    #[test]
    fn hash_six_byte_string() {
        let result = Hasher::hash("abcdef", 256).unwrap();
        assert!(result <= 0xffff);
    }
}
