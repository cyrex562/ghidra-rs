//! Port of `ghidra.features.bsim.query.protocol.ResponseVectorId`.
//!
//! Response to a `QueryVectorId` request to a BSim database. For each id in the request, return
//! a `VectorResult`, which contains the corresponding full vector, or `null`.

use std::io::{self, Write};

use crate::feature::bsim::query::description::VectorResult;
use crate::feature::bsim::query::lsh_exception::LshException;
use crate::feature::bsim::query::protocol::{QueryResponseRecord, QueryResponseRecordBase};
use crate::generic::lsh::vector::{LSHVector, LSHVectorFactory};
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_exception::XmlException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Response to a `QueryVectorId` request to a BSim database. For each id in the request, the
/// corresponding element is either `Some(VectorResult)`, or `None` if the database had no
/// vector for that id.
///
/// Java: `ResponseVectorId extends QueryResponseRecord`.
///
/// Generic over the concrete [`LSHVector`] implementation, matching
/// [`VectorResult`](crate::feature::bsim::query::description::VectorResult) (which is not
/// object-safe for the same reason -- see that type's docs).
pub struct ResponseVectorId<V: LSHVector> {
    /// List of result objects (or `None`) one per requested id.
    pub vector_results: Vec<Option<VectorResult<V>>>,

    base: QueryResponseRecordBase,
}

impl<V: LSHVector> ResponseVectorId<V> {
    /// Java: `ResponseVectorId()`.
    pub fn new() -> Self {
        Self { vector_results: Vec::new(), base: QueryResponseRecordBase::new("responsevectorid") }
    }

    /// Java: `getName()` (inherited from `QueryResponseRecord`).
    pub fn get_name(&self) -> &str {
        self.base.get_name()
    }

    /// Serializes this response as a `<responsevectorid>` element containing one child per
    /// entry in `vector_results`: `<null/>` for `None`, or the vector result's own XML for
    /// `Some`.
    ///
    /// Java: `saveXml(Writer)`.
    pub fn save_xml(&self, fwrite: &mut dyn Write) -> io::Result<()> {
        write!(fwrite, "<{}>\n", self.base.get_name())?;
        for vec_result in &self.vector_results {
            match vec_result {
                None => write!(fwrite, " <null/>\n")?,
                Some(vr) => {
                    // `VectorResult::save_xml` is generic over `W: Write` (implicitly `Sized`),
                    // so it can't be called directly with the `&mut dyn Write` this method
                    // receives; buffer its output and copy it through instead.
                    let mut vr_buf = Vec::new();
                    vr.save_xml(&mut vr_buf)?;
                    fwrite.write_all(&vr_buf)?;
                }
            }
        }
        write!(fwrite, "</{}>\n", self.base.get_name())
    }

    /// Deserializes a `ResponseVectorId` from its enclosing element, reading one `VectorResult`
    /// (or `<null/>`) per child.
    ///
    /// Java: `restoreXml(XmlPullParser, LSHVectorFactory)`. Java matches the outer element with
    /// a no-arg `parser.start()`/`parser.end()` pair (accepting whatever element is next, rather
    /// than checking its name), which this mirrors via `parser.start(&[])`/`parser.end()`.
    pub(crate) fn restore_xml<P, F>(&mut self, parser: &mut P, vector_factory: &F) -> Result<(), LshException>
    where
        P: XmlPullParser,
        F: LSHVectorFactory<Vector = V>,
    {
        let xml_err = |e: XmlException| LshException::new(e.to_string());
        parser.start(&[]).map_err(xml_err)?;
        while parser.peek().is_start() {
            if parser.peek().get_name() == "null" {
                parser.discard_sub_tree();
                self.vector_results.push(None);
            } else {
                let mut vec_result = VectorResult::empty();
                vec_result.restore_xml(parser, vector_factory).map_err(xml_err)?;
                self.vector_results.push(Some(vec_result));
            }
        }
        parser.end().map_err(xml_err)?;
        Ok(())
    }
}

impl<V: LSHVector> Default for ResponseVectorId<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V: LSHVector + Send + Sync> QueryResponseRecord for ResponseVectorId<V> {
    fn base(&self) -> &QueryResponseRecordBase {
        &self.base
    }

    fn save_xml(&self, fwrite: &mut dyn Write) -> io::Result<()> {
        Self::save_xml(self, fwrite)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generic::lsh::vector::hash_entry::HashEntry;
    use crate::generic::lsh::vector::idf_lookup::IdfLookup;
    use crate::generic::lsh::vector::lsh_vector_factory::LSHVectorFactoryBase;
    use crate::generic::lsh::vector::vector_compare::VectorCompare;
    use crate::generic::lsh::vector::weight_factory::WeightFactory;
    use crate::util::xml::xml_element_impl::XmlElementImpl;

    /// Minimal mock vector, following the pattern established in `vector_result.rs`'s own tests.
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

    #[derive(Default)]
    struct MockFactory {
        base: LSHVectorFactoryBase,
        next_tag: i32,
    }

    impl AsRef<LSHVectorFactoryBase> for MockFactory {
        fn as_ref(&self) -> &LSHVectorFactoryBase {
            &self.base
        }
    }
    impl AsMut<LSHVectorFactoryBase> for MockFactory {
        fn as_mut(&mut self) -> &mut LSHVectorFactoryBase {
            &mut self.base
        }
    }
    impl LSHVectorFactory for MockFactory {
        type Vector = MockVector;
        fn build_zero_vector(&self) -> MockVector {
            MockVector { tag: 0 }
        }
        fn build_vector(&self, _feature: &[i32]) -> MockVector {
            MockVector { tag: 0 }
        }
        fn restore_vector_from_xml<P: XmlPullParser>(&self, parser: &mut P) -> MockVector {
            parser.start(&[]).expect("mock vector element start");
            parser.end().expect("mock vector element end");
            MockVector { tag: self.next_tag }
        }
        fn restore_vector_from_sql(&self, _sql: &str) -> io::Result<MockVector> {
            Ok(MockVector { tag: 0 })
        }
    }

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

    fn start(name: &str) -> XmlElementImpl {
        XmlElementImpl::new(true, false, name, 0, Vec::new(), None, 0, 0).unwrap()
    }

    fn end_with_text(name: &str, text: &str) -> XmlElementImpl {
        XmlElementImpl::new(false, true, name, 0, Vec::new(), Some(text.to_string()), 0, 0).unwrap()
    }

    #[test]
    fn new_starts_empty() {
        let r: ResponseVectorId<MockVector> = ResponseVectorId::new();
        assert!(r.vector_results.is_empty());
        assert_eq!(r.get_name(), "responsevectorid");
    }

    #[test]
    fn default_matches_new() {
        let r: ResponseVectorId<MockVector> = ResponseVectorId::default();
        assert!(r.vector_results.is_empty());
    }

    #[test]
    fn save_xml_writes_null_for_none_entries() {
        let mut r: ResponseVectorId<MockVector> = ResponseVectorId::new();
        r.vector_results.push(None);
        let mut buf = Vec::new();
        r.save_xml(&mut buf).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "<responsevectorid>\n <null/>\n</responsevectorid>\n");
    }

    #[test]
    fn save_xml_writes_vector_result_for_some_entries() {
        let mut r: ResponseVectorId<MockVector> = ResponseVectorId::new();
        r.vector_results.push(Some(VectorResult::new(5, 1, 0.5, 1.0, MockVector { tag: 9 })));
        let mut buf = Vec::new();
        r.save_xml(&mut buf).unwrap();
        let xml = String::from_utf8(buf).unwrap();
        assert!(xml.starts_with("<responsevectorid>\n"));
        assert!(xml.contains("<vec id=\"0x5\">"));
        assert!(xml.contains("<mockvec tag=\"9\"/>"));
        assert!(xml.ends_with("</responsevectorid>\n"));
    }

    #[test]
    fn save_xml_mixes_null_and_populated_entries() {
        let mut r: ResponseVectorId<MockVector> = ResponseVectorId::new();
        r.vector_results.push(None);
        r.vector_results.push(Some(VectorResult::new(1, 0, 0.0, 0.0, MockVector { tag: 1 })));
        r.vector_results.push(None);
        let mut buf = Vec::new();
        r.save_xml(&mut buf).unwrap();
        let xml = String::from_utf8(buf).unwrap();
        assert_eq!(xml.matches(" <null/>\n").count(), 2);
        assert!(xml.contains("<vec id=\"0x1\">"));
    }

    #[test]
    fn restore_xml_reads_null_entry() {
        let mut parser = VecParser {
            elements: vec![
                start("responsevectorid"),
                start("null"),
                end_with_text("null", ""),
                end_with_text("responsevectorid", ""),
            ],
            pos: 0,
        };
        let factory = MockFactory::default();
        let mut r: ResponseVectorId<MockVector> = ResponseVectorId::new();
        r.restore_xml(&mut parser, &factory).unwrap();
        assert_eq!(r.vector_results.len(), 1);
        assert!(r.vector_results[0].is_none());
    }

    #[test]
    fn restore_xml_reads_populated_vector_result() {
        let mut parser = VecParser {
            elements: vec![
                start("responsevectorid"),
                {
                    let mut e = start("vec");
                    e.set_attribute("id", "0xa");
                    e
                },
                start("hit"),
                end_with_text("hit", "3"),
                start("sim"),
                end_with_text("sim", "0.75"),
                start("sig"),
                end_with_text("sig", "1.25"),
                start("mockvec"),
                end_with_text("mockvec", ""),
                end_with_text("vec", ""),
                end_with_text("responsevectorid", ""),
            ],
            pos: 0,
        };
        let factory = MockFactory { base: LSHVectorFactoryBase::default(), next_tag: 7 };
        let mut r: ResponseVectorId<MockVector> = ResponseVectorId::new();
        r.restore_xml(&mut parser, &factory).unwrap();
        assert_eq!(r.vector_results.len(), 1);
        let vr = r.vector_results[0].as_ref().unwrap();
        assert_eq!(vr.vectorid, 0xa);
        assert_eq!(vr.hitcount, 3);
        assert_eq!(vr.sim, 0.75);
        assert_eq!(vr.signif, 1.25);
        assert_eq!(vr.vec, Some(MockVector { tag: 7 }));
    }

    #[test]
    fn restore_xml_reads_multiple_mixed_entries() {
        let mut parser = VecParser {
            elements: vec![
                start("responsevectorid"),
                start("null"),
                end_with_text("null", ""),
                {
                    let mut e = start("vec");
                    e.set_attribute("id", "0x2");
                    e
                },
                start("hit"),
                end_with_text("hit", "0"),
                start("sim"),
                end_with_text("sim", "0"),
                start("sig"),
                end_with_text("sig", "0"),
                start("mockvec"),
                end_with_text("mockvec", ""),
                end_with_text("vec", ""),
                end_with_text("responsevectorid", ""),
            ],
            pos: 0,
        };
        let factory = MockFactory::default();
        let mut r: ResponseVectorId<MockVector> = ResponseVectorId::new();
        r.restore_xml(&mut parser, &factory).unwrap();
        assert_eq!(r.vector_results.len(), 2);
        assert!(r.vector_results[0].is_none());
        assert_eq!(r.vector_results[1].as_ref().unwrap().vectorid, 2);
    }

    #[test]
    fn restore_xml_empty_response_yields_no_results() {
        let mut parser =
            VecParser { elements: vec![start("responsevectorid"), end_with_text("responsevectorid", "")], pos: 0 };
        let factory = MockFactory::default();
        let mut r: ResponseVectorId<MockVector> = ResponseVectorId::new();
        r.restore_xml(&mut parser, &factory).unwrap();
        assert!(r.vector_results.is_empty());
    }

    #[test]
    fn query_response_record_trait_delegates() {
        let mut r: ResponseVectorId<MockVector> = ResponseVectorId::new();
        r.vector_results.push(None);
        let record: &dyn QueryResponseRecord = &r;
        assert_eq!(record.get_name(), "responsevectorid");
        let mut buf = Vec::new();
        record.save_xml(&mut buf).unwrap();
        assert!(String::from_utf8(buf).unwrap().contains("<null/>"));
    }
}
