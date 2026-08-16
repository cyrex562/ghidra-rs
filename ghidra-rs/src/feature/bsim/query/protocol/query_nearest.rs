//! Port of `ghidra.features.bsim.query.protocol.QueryNearest`.
//!
//! Query nearest matches within the database to a set of functions.

use std::io::{self, Write};

use crate::feature::bsim::query::description::DescriptionManager;
use crate::feature::bsim::query::lsh_exception::LshException;
use crate::feature::seam_stubs::{BSimFilter, LSHVectorFactory, ResponseNearest};
use crate::util::seam_stubs::XmlPullParser;
use crate::util::xml::spec_xml_utils;

/// The default value for the similarity threshold. This threshold is for how similar the
/// potential function is. This is a value from 0.0 to 1.0.
pub const DEFAULT_SIMILARITY_THRESHOLD: f64 = 0.7;

/// The default value for the significance threshold. This threshold is for how significant the
/// match is (for example, smaller function matches are less significant). Higher is more
/// significant. There is no upper bound.
pub const DEFAULT_SIGNIFICANCE_THRESHOLD: f64 = 0.0;

/// The default value for the maximum number of similar functions to return **for a given input
/// function**.
pub const DEFAULT_MAX_MATCHES: i32 = 100;

/// Query nearest matches within the database to a set of functions.
///
/// Java: `QueryNearest extends BSimQuery<ResponseNearest>`.
pub struct QueryNearest {
    /// Functions that should be queried.
    pub manage: DescriptionManager,

    /// The response object (same as `response` in the parent BSimQuery).
    pub nearresponse: Option<Box<dyn ResponseNearest>>,

    /// Similarity threshold for the query.
    pub thresh: f64,

    /// Significance threshold for the query.
    pub signifthresh: f64,

    /// Maximum number of results to return (per function).
    pub max: i32,

    /// Maximum number of unique vectors that can be returned. Zero means "no limit".
    pub vectormax: i32,

    /// Query for categories of any returned executable.
    pub fillin_categories: bool,

    /// Filters for the query.
    pub bsim_filter: Option<Box<dyn BSimFilter>>,

    name: &'static str,
}

impl QueryNearest {
    /// Create a new QueryNearest query with default settings.
    ///
    /// Java: `QueryNearest()`.
    pub fn new() -> Self {
        Self {
            manage: DescriptionManager::new(),
            nearresponse: None,
            thresh: DEFAULT_SIMILARITY_THRESHOLD,
            signifthresh: DEFAULT_SIGNIFICANCE_THRESHOLD,
            max: DEFAULT_MAX_MATCHES,
            vectormax: 0,
            fillin_categories: true,
            bsim_filter: None,
            name: "querynearest",
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
            // In the real implementation, ResponseNearest would be a concrete type
            // constructed with a back-reference to this query:
            // self.nearresponse = Some(Box::new(ResponseNearest::new(self)));
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
    pub fn get_local_staging_copy(&self) -> QueryNearest {
        let mut newq = QueryNearest::new();
        newq.thresh = self.thresh;
        newq.signifthresh = self.signifthresh;
        newq.max = self.max;
        newq.vectormax = self.vectormax;
        newq.fillin_categories = self.fillin_categories;
        if let Some(filter) = &self.bsim_filter {
            newq.bsim_filter = Some(filter.as_ref().clone());
        }
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
        write!(
            fwrite,
            "<max>{}</max>\n",
            spec_xml_utils::encode_signed_integer(self.max as i64)
        )?;
        if self.vectormax != 0 {
            write!(
                fwrite,
                "<vectormax>{}</vectormax>\n",
                spec_xml_utils::encode_signed_integer(self.vectormax as i64)
            )?;
        }
        if !self.fillin_categories {
            write!(fwrite, "<categories>false</categories>\n")?;
        }
        if let Some(filter) = &self.bsim_filter {
            filter.save_xml(fwrite)?;
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
        self.fillin_categories = true;
        // This would normally parse the XML element using the parser:
        // parser.start(self.name);
        // self.manage.restore_xml(parser, vector_factory)?;
        // parser.start("simthresh");
        // self.thresh = parser.end().get_text().parse().unwrap();
        // parser.start("signifthresh");
        // self.signifthresh = parser.end().get_text().parse().unwrap();
        // parser.start("max");
        // self.max = spec_xml_utils::decode_int(Some(parser.end().get_text()));
        // while parser.peek().is_start() {
        //     let el = parser.peek();
        //     match el.get_name() {
        //         "vectormax" => {
        //             parser.start();
        //             self.vectormax = spec_xml_utils::decode_int(Some(parser.end().get_text()));
        //         }
        //         "categories" => {
        //             parser.start();
        //             self.fillin_categories = spec_xml_utils::decode_boolean(parser.end().get_text());
        //         }
        //         "exefilter" => {
        //             let mut filter = BSimFilter::new();
        //             filter.restore_xml(parser);
        //             self.bsim_filter = Some(Box::new(filter));
        //         }
        //         other => return Err(LshException::new(format!("Unknown tag: {}", other))),
        //     }
        // }
        // parser.end();
        Ok(())
    }
}

impl Default for QueryNearest {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_nearest_new_default_config() {
        let query = QueryNearest::new();
        assert_eq!(query.thresh, DEFAULT_SIMILARITY_THRESHOLD);
        assert_eq!(query.signifthresh, DEFAULT_SIGNIFICANCE_THRESHOLD);
        assert_eq!(query.max, DEFAULT_MAX_MATCHES);
        assert_eq!(query.vectormax, 0);
        assert!(query.fillin_categories);
        assert!(query.bsim_filter.is_none());
        assert!(query.nearresponse.is_none());
        assert_eq!(query.get_name(), "querynearest");
        assert_eq!(query.manage.num_executables(), 0);
        assert_eq!(query.manage.num_functions(), 0);
    }

    #[test]
    fn test_query_nearest_default() {
        let query = QueryNearest::default();
        assert_eq!(query.get_name(), "querynearest");
        assert_eq!(query.thresh, DEFAULT_SIMILARITY_THRESHOLD);
    }

    #[test]
    fn test_query_nearest_get_description_manager() {
        let query = QueryNearest::new();
        let manage = query.get_description_manager();
        assert_eq!(manage.num_executables(), 0);
    }

    #[test]
    fn test_query_nearest_get_local_staging_copy_carries_thresholds() {
        let mut query = QueryNearest::new();
        query.thresh = 0.85;
        query.signifthresh = 2.5;
        query.max = 25;
        query.vectormax = 10;
        query.fillin_categories = false;

        let copy = query.get_local_staging_copy();
        assert_eq!(copy.thresh, 0.85);
        assert_eq!(copy.signifthresh, 2.5);
        assert_eq!(copy.max, 25);
        assert_eq!(copy.vectormax, 10);
        assert!(!copy.fillin_categories);
        // The staging copy does not carry over the description manager's contents.
        assert_eq!(copy.manage.num_executables(), 0);
    }

    #[test]
    fn test_query_nearest_build_response_template() {
        let mut query = QueryNearest::new();
        assert!(query.nearresponse.is_none());
        query.build_response_template();
        // Still none since ResponseNearest is not implemented yet.
        assert!(query.nearresponse.is_none());
    }

    #[test]
    fn test_query_nearest_save_xml_matches_java_behavior() {
        let query = QueryNearest::new();
        let mut buffer = Vec::new();
        let result = query.save_xml(&mut buffer);
        assert!(result.is_ok());

        let xml_str = String::from_utf8(buffer).unwrap();
        assert_eq!(
            xml_str,
            "<querynearest>\n<description layout_version=\"5\">\n</description>\n<simthresh>0.7</simthresh>\n<signifthresh>0</signifthresh>\n<max>100</max>\n</querynearest>\n"
        );
    }

    #[test]
    fn test_query_nearest_save_xml_with_vectormax_and_categories_false() {
        let mut query = QueryNearest::new();
        query.vectormax = 5;
        query.fillin_categories = false;

        let mut buffer = Vec::new();
        query.save_xml(&mut buffer).unwrap();
        let xml_str = String::from_utf8(buffer).unwrap();

        assert!(xml_str.contains("<vectormax>5</vectormax>\n"));
        assert!(xml_str.contains("<categories>false</categories>\n"));
    }

    #[test]
    fn test_query_nearest_restore_xml_stub_resets_defaults() {
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

        let mut query = QueryNearest::new();
        query.vectormax = 99;
        query.fillin_categories = false;
        let result = query.restore_xml(&DummyParser, &DummyVectorFactory);
        assert!(result.is_ok());
        // The stub resets these to their Java-documented defaults at the start of restoreXml.
        assert_eq!(query.vectormax, 0);
        assert!(query.fillin_categories);
    }
}
