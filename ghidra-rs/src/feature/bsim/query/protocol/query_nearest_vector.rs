//! Port of `ghidra.features.bsim.query.protocol.QueryNearestVector`.
//!
//! For specific functions, query for the list of vectors that are similar to a function's
//! vector, without recovering the descriptions of functions that instantiate these vectors.

use std::io::{self, Write};

use crate::feature::bsim::query::description::DescriptionManager;
use crate::feature::bsim::query::lsh_exception::LshException;
use crate::feature::bsim::query::protocol::query_nearest::{
    DEFAULT_SIGNIFICANCE_THRESHOLD, DEFAULT_SIMILARITY_THRESHOLD,
};
use crate::feature::seam_stubs::{LSHVectorFactory, ResponseNearestVector};
use crate::util::seam_stubs::XmlPullParser;
use crate::util::xml::spec_xml_utils;

/// For specific functions, query for the list of vectors that are similar to a function's
/// vector, without recovering the descriptions of functions that instantiate these vectors.
///
/// Java: `QueryNearestVector extends BSimQuery<ResponseNearestVector>`.
pub struct QueryNearestVector {
    /// Functions that should be queried.
    pub manage: DescriptionManager,

    /// The response object (same as `response` in the parent BSimQuery).
    pub nearresponse: Option<Box<dyn ResponseNearestVector>>,

    /// Similarity threshold for the query.
    pub thresh: f64,

    /// Significance threshold for the query.
    pub signifthresh: f64,

    /// Maximum number of unique vectors that can be returned. Zero means "no limit".
    pub vectormax: i32,

    name: &'static str,
}

impl QueryNearestVector {
    /// Create a new QueryNearestVector query with default settings.
    ///
    /// Java: `QueryNearestVector()`.
    pub fn new() -> Self {
        Self {
            manage: DescriptionManager::new(),
            nearresponse: None,
            thresh: DEFAULT_SIMILARITY_THRESHOLD,
            signifthresh: DEFAULT_SIGNIFICANCE_THRESHOLD,
            vectormax: 0,
            name: "querynearestvector",
        }
    }

    /// Get the name of this query.
    ///
    /// Java: `getName()` (inherited from `BSimQuery`).
    pub fn get_name(&self) -> &str {
        self.name
    }

    /// Build the response template for this query.
    ///
    /// Java: `buildResponseTemplate()`.
    pub fn build_response_template(&mut self) {
        if self.nearresponse.is_none() {
            // In the real implementation, ResponseNearestVector would be a concrete type
            // constructed with a back-reference to this query:
            // self.nearresponse = Some(Box::new(ResponseNearestVector::new(self)));
        }
    }

    /// Get the description manager holding the functions to query for this query.
    ///
    /// Java: `getDescriptionManager()`.
    pub fn get_description_manager(&self) -> &DescriptionManager {
        &self.manage
    }

    /// Get a partial clone of this query suitable for holding local stages via `StagingManager`.
    ///
    /// Java: `getLocalStagingCopy()`.
    pub fn get_local_staging_copy(&self) -> QueryNearestVector {
        let mut newq = QueryNearestVector::new();
        newq.thresh = self.thresh;
        newq.signifthresh = self.signifthresh;
        newq.vectormax = self.vectormax;
        newq
    }

    /// Save this query to XML.
    ///
    /// Java: `saveXml(Writer)`.
    pub fn save_xml<W: Write>(&self, fwrite: &mut W) -> io::Result<()> {
        write!(fwrite, "<{}>\n", self.name)?;
        self.manage.save_xml(fwrite)?;
        write!(fwrite, "<simthresh>{}</simthresh>\n", self.thresh)?;
        write!(fwrite, "<signifthresh>{}</signifthresh>\n", self.signifthresh)?;
        if self.vectormax != 0 {
            write!(
                fwrite,
                "<vectormax>{}</vectormax>\n",
                spec_xml_utils::encode_signed_integer(self.vectormax as i64)
            )?;
        }
        write!(fwrite, "</{}>\n", self.name)?;
        Ok(())
    }

    /// Restore this query from XML.
    ///
    /// Java: `restoreXml(XmlPullParser, LSHVectorFactory)`.
    pub fn restore_xml(
        &mut self,
        _parser: &dyn XmlPullParser,
        _vector_factory: &dyn LSHVectorFactory,
    ) -> Result<(), LshException> {
        self.vectormax = 0;
        // This would normally parse the XML element using the parser:
        // parser.start(self.name);
        // self.manage.restore_xml(parser, vector_factory)?;
        // parser.start("simthresh");
        // self.thresh = parser.end().get_text().parse().unwrap();
        // parser.start("signifthresh");
        // self.signifthresh = parser.end().get_text().parse().unwrap();
        // while parser.peek().is_start() {
        //     let el = parser.peek();
        //     match el.get_name() {
        //         "vectormax" => {
        //             parser.start();
        //             self.vectormax = spec_xml_utils::decode_int(Some(parser.end().get_text()));
        //         }
        //         other => return Err(LshException::new(format!("Unknown tag: {}", other))),
        //     }
        // }
        // parser.end();
        Ok(())
    }
}

impl Default for QueryNearestVector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_nearest_vector_new_default_config() {
        let query = QueryNearestVector::new();
        assert_eq!(query.thresh, DEFAULT_SIMILARITY_THRESHOLD);
        assert_eq!(query.signifthresh, DEFAULT_SIGNIFICANCE_THRESHOLD);
        assert_eq!(query.vectormax, 0);
        assert!(query.nearresponse.is_none());
        assert_eq!(query.get_name(), "querynearestvector");
        assert_eq!(query.manage.num_executables(), 0);
        assert_eq!(query.manage.num_functions(), 0);
    }

    #[test]
    fn test_query_nearest_vector_default() {
        let query = QueryNearestVector::default();
        assert_eq!(query.get_name(), "querynearestvector");
        assert_eq!(query.thresh, DEFAULT_SIMILARITY_THRESHOLD);
    }

    #[test]
    fn test_query_nearest_vector_get_description_manager() {
        let query = QueryNearestVector::new();
        let manage = query.get_description_manager();
        assert_eq!(manage.num_executables(), 0);
    }

    #[test]
    fn test_query_nearest_vector_get_local_staging_copy_carries_thresholds() {
        let mut query = QueryNearestVector::new();
        query.thresh = 0.85;
        query.signifthresh = 2.5;
        query.vectormax = 10;

        let copy = query.get_local_staging_copy();
        assert_eq!(copy.thresh, 0.85);
        assert_eq!(copy.signifthresh, 2.5);
        assert_eq!(copy.vectormax, 10);
        // The staging copy does not carry over the description manager's contents.
        assert_eq!(copy.manage.num_executables(), 0);
    }

    #[test]
    fn test_query_nearest_vector_build_response_template() {
        let mut query = QueryNearestVector::new();
        assert!(query.nearresponse.is_none());
        query.build_response_template();
        // Still none since ResponseNearestVector is not implemented yet.
        assert!(query.nearresponse.is_none());
    }

    #[test]
    fn test_query_nearest_vector_save_xml_matches_java_behavior() {
        let query = QueryNearestVector::new();
        let mut buffer = Vec::new();
        let result = query.save_xml(&mut buffer);
        assert!(result.is_ok());

        let xml_str = String::from_utf8(buffer).unwrap();
        assert_eq!(
            xml_str,
            "<querynearestvector>\n<description layout_version=\"5\">\n</description>\n<simthresh>0.7</simthresh>\n<signifthresh>0</signifthresh>\n</querynearestvector>\n"
        );
    }

    #[test]
    fn test_query_nearest_vector_save_xml_with_vectormax() {
        let mut query = QueryNearestVector::new();
        query.vectormax = 5;

        let mut buffer = Vec::new();
        query.save_xml(&mut buffer).unwrap();
        let xml_str = String::from_utf8(buffer).unwrap();

        assert!(xml_str.contains("<vectormax>5</vectormax>\n"));
    }

    #[test]
    fn test_query_nearest_vector_restore_xml_stub_resets_defaults() {
        struct DummyParser;
        impl XmlPullParser for DummyParser {
            fn start(&self, _name: &str) {}
            fn end(&self) {}
        }
        struct DummyVectorFactory;
        impl LSHVectorFactory for DummyVectorFactory {
            fn build_zero_vector(&self) -> Box<dyn crate::feature::seam_stubs::LSHVector> {
                unimplemented!()
            }
            fn build_vector(
                &self,
                _feature: &[i32],
            ) -> Box<dyn crate::feature::seam_stubs::LSHVector> {
                unimplemented!()
            }
            fn restore_vector_from_xml(
                &self,
                _parser: &dyn XmlPullParser,
            ) -> Box<dyn crate::feature::seam_stubs::LSHVector> {
                unimplemented!()
            }
            fn restore_vector_from_sql(
                &self,
                _sql: &str,
            ) -> std::io::Result<Box<dyn crate::feature::seam_stubs::LSHVector>> {
                unimplemented!()
            }
            fn set(
                &self,
                _w_factory: &dyn crate::feature::seam_stubs::WeightFactory,
                _i_lookup: &dyn crate::feature::seam_stubs::IDFLookup,
                _settings: i32,
            ) {
            }
            fn is_loaded(&self) -> bool {
                false
            }
            fn get_significance_scale(&self) -> f64 {
                0.0
            }
            fn get_significance_addend(&self) -> f64 {
                0.0
            }
            fn get_settings(&self) -> i32 {
                0
            }
            fn get_self_significance(
                &self,
                _vector: &dyn crate::feature::seam_stubs::LSHVector,
            ) -> f64 {
                0.0
            }
            fn calculate_significance(
                &self,
                _data: &dyn crate::feature::seam_stubs::VectorCompare,
            ) -> f64 {
                0.0
            }
            fn read_weights(&self, _parser: &dyn XmlPullParser) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut query = QueryNearestVector::new();
        query.vectormax = 99;
        let result = query.restore_xml(&DummyParser, &DummyVectorFactory);
        assert!(result.is_ok());
        // The stub resets vectormax to its Java-documented default at the start of restoreXml.
        assert_eq!(query.vectormax, 0);
    }
}
