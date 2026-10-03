//! Port of `ghidra.features.bsim.query.file.VectorStoreEntry`.

use crate::generic::lsh::vector::LSHVector;

/// A record containing an [`LSHVector`] and a count of the number of functions in the database
/// which share the vector.
///
/// Port of `ghidra.features.bsim.query.file.VectorStoreEntry`, a Java `record`:
///
/// ```java
/// public record VectorStoreEntry(long id, LSHVector vec, int count, double selfSig) {
/// }
/// ```
///
/// Generic over the concrete [`LSHVector`] implementation for the same reason as
/// [`VectorResult`](crate::feature::bsim::query::description::VectorResult) and
/// [`SignatureRecord`](crate::feature::bsim::query::description::signature_record::SignatureRecord):
/// [`LSHVector`] is not object safe (several of its methods are themselves generic), so a type
/// parameter `V` stands in for `dyn LSHVector`.
#[derive(Debug, Clone)]
pub struct VectorStoreEntry<V: LSHVector> {
    id: i64,
    vec: V,
    count: i32,
    self_sig: f64,
}

impl<V: LSHVector> VectorStoreEntry<V> {
    /// Port of the record's canonical constructor `VectorStoreEntry(long id, LSHVector vec, int
    /// count, double selfSig)`.
    pub fn new(id: i64, vec: V, count: i32, self_sig: f64) -> Self {
        VectorStoreEntry { id, vec, count, self_sig }
    }

    /// Vector ID. Port of the record accessor `id()`.
    pub fn id(&self) -> i64 {
        self.id
    }

    /// The vector itself. Port of the record accessor `vec()`.
    pub fn vec(&self) -> &V {
        &self.vec
    }

    /// Count of the number of functions in the database which share the vector. Port of the
    /// record accessor `count()`.
    pub fn count(&self) -> i32 {
        self.count
    }

    /// Self-significance of vector (using database settings). Port of the record accessor
    /// `selfSig()`.
    pub fn self_sig(&self) -> f64 {
        self.self_sig
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generic::lsh::vector::hash_entry::HashEntry;
    use crate::generic::lsh::vector::idf_lookup::IdfLookup;
    use crate::generic::lsh::vector::vector_compare::VectorCompare;
    use crate::generic::lsh::vector::weight_factory::WeightFactory;
    use crate::util::xml::xml_pull_parser::XmlPullParser;
    use std::io::{self, Write};

    /// Minimal mock vector, following the pattern established in `lsh_vector.rs`'s own tests and
    /// `VectorResult`'s tests.
    #[derive(Debug, Clone, PartialEq)]
    struct MockVector {
        tag: i32,
    }

    impl LSHVector for MockVector {
        fn num_entries(&self) -> i32 {
            1
        }
        fn get_entry(&self, _i: i32) -> Option<HashEntry> {
            None
        }
        fn get_entries(&self) -> Vec<HashEntry> {
            Vec::new()
        }
        fn get_length(&self) -> f64 {
            0.0
        }
        fn compare<T: LSHVector + ?Sized>(&self, _op2: &T, _data: &mut VectorCompare) -> f64 {
            0.0
        }
        fn compare_counts<T: LSHVector + ?Sized>(&self, _op2: &T, _data: &mut VectorCompare) {}
        fn compare_detail<T: LSHVector + ?Sized>(&self, _op2: &T, _buf: &mut String) -> f64 {
            0.0
        }
        fn save_xml(&self, fwrite: &mut dyn Write) -> io::Result<()> {
            write!(fwrite, "<mockvec tag=\"{}\"/>", self.tag)
        }
        fn save_sql(&self) -> String {
            String::new()
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
            self.tag as u64
        }
    }

    #[test]
    fn new_stores_all_four_components() {
        let entry = VectorStoreEntry::new(42, MockVector { tag: 7 }, 3, 0.85);

        assert_eq!(entry.id(), 42);
        assert_eq!(entry.vec(), &MockVector { tag: 7 });
        assert_eq!(entry.count(), 3);
        assert_eq!(entry.self_sig(), 0.85);
    }

    #[test]
    fn accessors_reflect_constructor_argument_order() {
        let a = VectorStoreEntry::new(1, MockVector { tag: 1 }, 10, 0.1);
        let b = VectorStoreEntry::new(2, MockVector { tag: 2 }, 20, 0.2);

        assert_ne!(a.id(), b.id());
        assert_ne!(a.vec(), b.vec());
        assert_ne!(a.count(), b.count());
        assert_ne!(a.self_sig(), b.self_sig());
    }

    #[test]
    fn clone_produces_an_independent_equal_copy() {
        let entry = VectorStoreEntry::new(9, MockVector { tag: 3 }, 1, 0.5);
        let cloned = entry.clone();

        assert_eq!(entry.id(), cloned.id());
        assert_eq!(entry.vec(), cloned.vec());
        assert_eq!(entry.count(), cloned.count());
        assert_eq!(entry.self_sig(), cloned.self_sig());
    }
}
