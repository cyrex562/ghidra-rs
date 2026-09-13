//! Port of `ghidra.features.bsim.query.description.SignatureRecord`.

use std::io::{self, Write};
use std::sync::Arc;

use crate::feature::bsim::query::description::{DescriptionManager, FunctionDescription};
use crate::feature::bsim::query::LshException;
use crate::generic::lsh::vector::LSHVector;
use crate::generic::seam_stubs::{LSHVectorFactory, WeightedLSHCosineVector};
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// A feature vector generated for one or more functions, plus bookkeeping about how many
/// functions in the container share it and the database id assigned to it.
///
/// Port of `ghidra.features.bsim.query.description.SignatureRecord`.
///
/// Generic over the concrete [`LSHVector`] implementation, mirroring the Java class's reliance
/// on the abstract `LSHVector` interface: [`LSHVector`]'s comparison methods are generic over
/// their argument type (see its docs), which makes the trait not object safe, so a type
/// parameter is this crate's established seam in place of `dyn LSHVector` (see e.g.
/// [`LSHVectorFactory::Vector`](crate::generic::lsh::vector::LSHVectorFactory::Vector)).
#[derive(Debug, Clone)]
pub struct SignatureRecord<V: LSHVector> {
    /// Vector of signatures.
    sigvector: V,
    /// Vectorid of signature.
    vectorid: i64,
    /// Number of duplicates of this signature within the database.
    count: i32,
}

impl<V: LSHVector> SignatureRecord<V> {
    /// Java: `SignatureRecord(LSHVector v)`.
    ///
    /// Java shares `v` by reference (the new record and the caller alias the same object); Rust
    /// takes ownership of `v` instead, so callers that still need the vector should clone it
    /// first. [`DescriptionManager::new_signature`] is one such caller.
    pub fn new(v: V) -> Self {
        Self { sigvector: v, vectorid: 0, count: 0 }
    }

    /// Java: package-private `setVectorId(long)`.
    pub(crate) fn set_vector_id(&mut self, i: i64) {
        self.vectorid = i;
    }

    /// Java: package-private `setCount(int)`.
    pub(crate) fn set_count(&mut self, c: i32) {
        self.count = c;
    }

    /// Java: `getLSHVector()`.
    pub fn get_lsh_vector(&self) -> &V {
        &self.sigvector
    }

    /// Java: `getVectorId()`.
    pub fn get_vector_id(&self) -> i64 {
        self.vectorid
    }

    /// Java: `getCount()`, the number of functions sharing this signature.
    pub fn get_count(&self) -> i32 {
        self.count
    }

    /// Java: `saveXml(Writer)`, which delegates entirely to the vector's `saveXml`.
    pub fn save_xml<W: Write>(&self, fwrite: &mut W) -> io::Result<()> {
        self.sigvector.save_xml(fwrite)
    }

    /// Java: `hashCode()` (`31 * 1 + sigvector.hashCode()`). [`LSHVector`] has no `hashCode`
    /// analog of its own, so [`LSHVector::calc_unique_hash`] -- the trait's purpose-built
    /// identity hash -- stands in for `sigvector.hashCode()`.
    pub fn hash_code(&self) -> u64 {
        31u64.wrapping_add(self.sigvector.calc_unique_hash())
    }
}

impl<V: LSHVector + PartialEq> PartialEq for SignatureRecord<V> {
    /// Java: `equals(Object)`, which compares `sigvector` alone -- `vectorid` and `count` do not
    /// take part.
    fn eq(&self, other: &Self) -> bool {
        self.sigvector == other.sigvector
    }
}

impl<V: LSHVector + Eq> Eq for SignatureRecord<V> {}

impl SignatureRecord<WeightedLSHCosineVector> {
    /// Java: `static void restoreXml(XmlPullParser parser, LSHVectorFactory vectorFactory,
    /// DescriptionManager man, FunctionDescription fdesc, int count)`.
    ///
    /// Builds a record through the manager (fixed at the concrete
    /// [`WeightedLSHCosineVector`], the only [`LSHVector`] implementation currently wired
    /// through [`DescriptionManager`]) and attaches it to `fdesc`.
    pub(crate) fn restore_xml<P: XmlPullParser>(
        parser: &mut P,
        vector_factory: &LSHVectorFactory,
        man: &mut DescriptionManager,
        fdesc: &mut FunctionDescription,
        count: i32,
    ) -> Result<(), LshException> {
        let srec = man.new_signature_from_xml(parser, vector_factory, count);
        man.attach_signature(fdesc, Arc::new(srec));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generic::lsh::vector::hash_entry::HashEntry;
    use crate::generic::lsh::vector::vector_compare::VectorCompare;
    use crate::generic::lsh::vector::weight_factory::WeightFactory;
    use crate::generic::seam_stubs::WeightedLSHCosineVector;

    /// Minimal mock vector so tests do not depend on the still-inert `WeightedLSHCosineVector`
    /// serialization methods. Mirrors the pattern already established in `lsh_vector.rs`'s own
    /// tests.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MockVector {
        hash: u64,
        saved: std::cell::RefCell<Option<String>>,
    }

    impl MockVector {
        fn new(hash: u64) -> Self {
            Self { hash, saved: std::cell::RefCell::new(None) }
        }
    }

    impl LSHVector for MockVector {
        fn num_entries(&self) -> i32 {
            0
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
            write!(fwrite, "<vec hash=\"{}\"/>", self.hash)?;
            *self.saved.borrow_mut() = Some(format!("{}", self.hash));
            Ok(())
        }
        fn save_sql(&self) -> String {
            String::new()
        }
        fn save_base64(&self, _buffer: &mut [char], _encoder: &[char]) {}
        fn restore_xml<P: XmlPullParser>(
            &mut self,
            _parser: &mut P,
            _weight_factory: &WeightFactory,
            _idf_lookup: &crate::generic::lsh::vector::idf_lookup::IdfLookup,
        ) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }
        fn restore_sql(
            &mut self,
            _sql: &str,
            _weight_factory: &WeightFactory,
            _idf_lookup: &crate::generic::lsh::vector::idf_lookup::IdfLookup,
        ) -> io::Result<()> {
            Ok(())
        }
        fn restore_base64(
            &mut self,
            _input: &mut dyn std::io::Read,
            _buffer: &[char],
            _wfactory: &WeightFactory,
            _idflookup: &crate::generic::lsh::vector::idf_lookup::IdfLookup,
            _decode: &[i32],
        ) -> io::Result<()> {
            Ok(())
        }
        fn calc_unique_hash(&self) -> u64 {
            self.hash
        }
    }

    // --- construction / accessors ---

    #[test]
    fn new_matches_java_defaults() {
        let srec = SignatureRecord::new(MockVector::new(42));
        assert_eq!(srec.get_vector_id(), 0);
        assert_eq!(srec.get_count(), 0);
        assert_eq!(srec.get_lsh_vector(), &MockVector::new(42));
    }

    #[test]
    fn set_vector_id_and_count() {
        let mut srec = SignatureRecord::new(MockVector::new(1));
        srec.set_vector_id(99);
        srec.set_count(4);
        assert_eq!(srec.get_vector_id(), 99);
        assert_eq!(srec.get_count(), 4);
    }

    // --- save_xml ---

    #[test]
    fn save_xml_delegates_to_the_vector() {
        let srec = SignatureRecord::new(MockVector::new(7));
        let mut buf = Vec::new();
        srec.save_xml(&mut buf).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "<vec hash=\"7\"/>");
    }

    // --- equals / hashCode ---

    #[test]
    fn equals_compares_the_vector_alone() {
        // Java: `equals` only ever looks at `sigvector`; two records with equal vectors but
        // different count/vectorid are still equal.
        let mut a = SignatureRecord::new(MockVector::new(5));
        a.set_count(3);
        a.set_vector_id(10);
        let b = SignatureRecord::new(MockVector::new(5));
        assert_eq!(a, b);
    }

    #[test]
    fn equals_differs_when_vectors_differ() {
        let a = SignatureRecord::new(MockVector::new(5));
        let b = SignatureRecord::new(MockVector::new(6));
        assert_ne!(a, b);
    }

    #[test]
    fn hash_code_matches_java_formula() {
        // Java: `31 * 1 + sigvector.hashCode()`.
        let srec = SignatureRecord::new(MockVector::new(11));
        assert_eq!(srec.hash_code(), 31 + 11);
    }

    // --- restore_xml / DescriptionManager integration ---

    #[test]
    fn restore_xml_attaches_a_signature_with_the_requested_count() {
        use crate::feature::seam_stubs::ExecutableRecord;
        use crate::util::xml::xml_element_impl::XmlElementImpl;

        struct VecParser {
            elements: Vec<XmlElementImpl>,
            pos: usize,
        }
        impl XmlPullParser for VecParser {
            type Element = XmlElementImpl;
            fn get_name(&self) -> &str {
                "VecParser"
            }
            fn get_processing_instruction(&self, _name: &str, _attribute: &str) -> Option<String> {
                None
            }
            fn is_pulling_content(&self) -> bool {
                true
            }
            fn set_pulling_content(&mut self, _pulling_content: bool) {}
            fn has_next(&self) -> bool {
                self.pos < self.elements.len()
            }
            fn peek(&self) -> Self::Element {
                self.elements[self.pos].clone()
            }
            fn next(&mut self) -> Self::Element {
                let el = self.elements[self.pos].clone();
                self.pos += 1;
                el
            }
            fn dispose(&mut self) {}
        }

        // A single empty `<lshcosine/>` start+end pair, which `discard_sub_tree`'s default
        // implementation (driven by `next`/`has_next`) consumes.
        let start = XmlElementImpl::new(true, false, "lshcosine", 0, Vec::new(), None, 0, 0).unwrap();
        let end =
            XmlElementImpl::new(false, true, "lshcosine", 0, Vec::new(), Some(String::new()), 0, 0)
                .unwrap();
        let mut parser = VecParser { elements: vec![start, end], pos: 0 };

        let mut man = DescriptionManager::new();
        let erec = Arc::new(ExecutableRecord::new("aa", "a.exe", "x86:LE:32:default", "gcc"));
        let mut fdesc = man.new_function_description("main", 0x1000, erec);

        SignatureRecord::<WeightedLSHCosineVector>::restore_xml(
            &mut parser,
            &LSHVectorFactory::default(),
            &mut man,
            &mut fdesc,
            5,
        )
        .unwrap();

        assert_eq!(fdesc.get_signature_record().unwrap().get_count(), 5);
        assert!(!parser.has_next());
    }
}
