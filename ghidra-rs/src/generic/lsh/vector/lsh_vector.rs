use std::io::{self, Write};

use crate::generic::lsh::vector::hash_entry::HashEntry;
use crate::generic::lsh::vector::idf_lookup::IdfLookup;
use crate::generic::lsh::vector::weight_factory::WeightFactory;
use crate::generic::seam_stubs::VectorCompare;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// A Locality Sensitive Hashing vector for fast similarity comparison.
///
/// Port of `generic.lsh.vector.LSHVector`.
///
/// This is an open extension point: concrete implementations can add their own
/// specific behaviors beyond this base interface. Most methods use generic
/// parameters for type-safe, zero-overhead polymorphism. Call sites should use
/// `impl LSHVector` or generic type parameters rather than attempting to create
/// trait objects.
pub trait LSHVector {
    /// Returns the number of entries in this vector.
    fn num_entries(&self) -> i32;

    /// Returns the entry at the specified index.
    fn get_entry(&self, i: i32) -> Option<HashEntry>;

    /// Returns all entries in this vector.
    fn get_entries(&self) -> Vec<HashEntry>;

    /// Returns the Euclidean length (magnitude) of this vector.
    fn get_length(&self) -> f64;

    /// Compares this vector with another using the provided comparison data.
    ///
    /// Returns a similarity measure (semantics depend on the implementation and
    /// the `VectorCompare` data provided).
    fn compare<T: LSHVector + ?Sized>(
        &self,
        op2: &T,
        data: &dyn VectorCompare,
    ) -> f64;

    /// Fills in the comparison data with count information by comparing this
    /// vector with another.
    fn compare_counts<T: LSHVector + ?Sized>(
        &self,
        op2: &T,
        data: &dyn VectorCompare,
    );

    /// Compares this vector with another, appending detailed information to
    /// the provided buffer.
    ///
    /// Returns a similarity measure or score derived from the comparison.
    fn compare_detail<T: LSHVector + ?Sized>(
        &self,
        op2: &T,
        buf: &mut String,
    ) -> f64;

    /// Serializes this vector to XML format.
    fn save_xml(&self, fwrite: &mut dyn Write) -> io::Result<()>;

    /// Serializes this vector to SQL format, returning the SQL string.
    fn save_sql(&self) -> String;

    /// Serializes this vector to base64 format into the provided buffer.
    ///
    /// `encoder` is a character array for base64 encoding (typically 64 chars).
    fn save_base64(&self, buffer: &mut [char], encoder: &[char]);

    /// Deserializes this vector from an XML stream.
    fn restore_xml<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
        weight_factory: &WeightFactory,
        idf_lookup: &IdfLookup,
    ) -> Result<(), Box<dyn std::error::Error>>;

    /// Deserializes this vector from an SQL string.
    fn restore_sql(
        &mut self,
        sql: &str,
        weight_factory: &WeightFactory,
        idf_lookup: &IdfLookup,
    ) -> io::Result<()>;

    /// Deserializes this vector from base64 format.
    ///
    /// `input` is the base64-encoded reader, `buffer` is a temporary character buffer,
    /// `wfactory` is the weight factory, `idflookup` is the IDF lookup table,
    /// and `decode` is an array for base64 decoding.
    fn restore_base64(
        &mut self,
        input: &mut dyn std::io::Read,
        buffer: &[char],
        wfactory: &WeightFactory,
        idflookup: &IdfLookup,
        decode: &[i32],
    ) -> io::Result<()>;

    /// Calculates a unique hash for this vector's identity.
    ///
    /// This hash is stable within a session but should not be relied upon
    /// for persistence or comparison across sessions.
    fn calc_unique_hash(&self) -> u64;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock implementation of LSHVector for testing.
    struct MockLSHVector {
        entries: Vec<HashEntry>,
        length: f64,
        unique_hash: u64,
    }

    impl MockLSHVector {
        fn new(entries: Vec<HashEntry>, length: f64) -> Self {
            let unique_hash = entries.iter().map(|e| e.get_hash() as u64).sum();
            Self { entries, length, unique_hash }
        }
    }

    impl LSHVector for MockLSHVector {
        fn num_entries(&self) -> i32 {
            self.entries.len() as i32
        }

        fn get_entry(&self, i: i32) -> Option<HashEntry> {
            if i >= 0 && (i as usize) < self.entries.len() {
                Some(self.entries[i as usize])
            } else {
                None
            }
        }

        fn get_entries(&self) -> Vec<HashEntry> {
            self.entries.clone()
        }

        fn get_length(&self) -> f64 {
            self.length
        }

        fn compare<T: LSHVector + ?Sized>(
            &self,
            _op2: &T,
            _data: &dyn VectorCompare,
        ) -> f64 {
            0.5
        }

        fn compare_counts<T: LSHVector + ?Sized>(
            &self,
            _op2: &T,
            _data: &dyn VectorCompare,
        ) {}

        fn compare_detail<T: LSHVector + ?Sized>(
            &self,
            _op2: &T,
            _buf: &mut String,
        ) -> f64 {
            0.25
        }

        fn save_xml(&self, _fwrite: &mut dyn Write) -> io::Result<()> {
            Ok(())
        }

        fn save_sql(&self) -> String {
            "mock_sql".to_string()
        }

        fn save_base64(&self, _buffer: &mut [char], _encoder: &[char]) {}

        fn restore_xml<P: XmlPullParser>(
            &mut self,
            _parser: &mut P,
            _weight_factory: &WeightFactory,
            _idf_lookup: &IdfLookup,
        ) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }

        fn restore_sql(
            &mut self,
            _sql: &str,
            _weight_factory: &WeightFactory,
            _idf_lookup: &IdfLookup,
        ) -> io::Result<()> {
            Ok(())
        }

        fn restore_base64(
            &mut self,
            _input: &mut dyn std::io::Read,
            _buffer: &[char],
            _wfactory: &WeightFactory,
            _idflookup: &IdfLookup,
            _decode: &[i32],
        ) -> io::Result<()> {
            Ok(())
        }

        fn calc_unique_hash(&self) -> u64 {
            self.unique_hash
        }
    }

    struct MockVectorCompare;

    impl VectorCompare for MockVectorCompare {
        fn fill_out(&self) {}
        fn to_string(&self) -> String {
            "mock_compare".to_string()
        }
    }

    #[test]
    fn test_lsh_vector_trait_basic() {
        let entry1 = HashEntry::with_weight(42, 3, 1.5);
        let entry2 = HashEntry::with_weight(99, 5, 2.1);
        let entries = vec![entry1, entry2];

        let vec = MockLSHVector::new(entries, 3.2);

        assert_eq!(vec.num_entries(), 2);
        assert_eq!(vec.get_length(), 3.2);
        assert_eq!(vec.get_entry(0).unwrap().get_hash(), 42);
        assert_eq!(vec.get_entry(1).unwrap().get_hash(), 99);
        assert_eq!(vec.get_entry(2), None);

        let all_entries = vec.get_entries();
        assert_eq!(all_entries.len(), 2);
        assert_eq!(all_entries[0].get_hash(), 42);
    }

    #[test]
    fn test_lsh_vector_trait_empty() {
        let vec = MockLSHVector::new(vec![], 0.0);

        assert_eq!(vec.num_entries(), 0);
        assert_eq!(vec.get_length(), 0.0);
        assert_eq!(vec.get_entry(0), None);
        assert!(vec.get_entries().is_empty());
    }

    #[test]
    fn test_lsh_vector_unique_hash() {
        let entry1 = HashEntry::with_weight(42, 3, 1.5);
        let entry2 = HashEntry::with_weight(99, 5, 2.1);
        let entries = vec![entry1, entry2];

        let vec = MockLSHVector::new(entries, 3.2);
        let hash = vec.calc_unique_hash();

        assert_eq!(hash, 42 + 99);
    }
}
