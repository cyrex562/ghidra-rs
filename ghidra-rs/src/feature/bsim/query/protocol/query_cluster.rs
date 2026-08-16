//! Port of `ghidra.features.bsim.query.protocol.QueryCluster`.
//!
//! Query based on a set of functions that should be used as roots of separate similarity
//! clusters, subject to a similarity and significance threshold.

use std::io::{self, Write};

use crate::feature::bsim::query::description::DescriptionManager;
use crate::feature::bsim::query::lsh_exception::LshException;
use crate::feature::seam_stubs::{LSHVectorFactory, ResponseCluster};
use crate::util::seam_stubs::XmlPullParser;
use crate::util::xml::spec_xml_utils;

/// Query based on a set of functions that should be used as cluster roots.
///
/// Java: `QueryCluster extends BSimQuery<ResponseCluster>`.
pub struct QueryCluster {
    /// Functions that should be queried as cluster roots.
    pub manage: DescriptionManager,

    /// The response object (same as `response` in the parent BSimQuery).
    pub clusterresponse: Option<Box<dyn ResponseCluster>>,

    /// Similarity limit of the cluster.
    pub thresh: f64,

    /// Significance limit of the cluster.
    pub signifthresh: f64,

    /// Maximum number of vector results per function.
    pub vectormax: i32,

    name: &'static str,
}

impl QueryCluster {
    /// Create a new QueryCluster query with default settings.
    ///
    /// Java: `QueryCluster()`.
    pub fn new() -> Self {
        Self {
            manage: DescriptionManager::new(),
            clusterresponse: None,
            // Some reasonable defaults.
            thresh: 0.9,
            signifthresh: 0.0,
            vectormax: 50,
            name: "querycluster",
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
        if self.clusterresponse.is_none() {
            // In the real implementation, ResponseCluster would be a concrete type
            // constructed with a back-reference to this query:
            // self.clusterresponse = Some(Box::new(ResponseCluster::new(self)));
        }
    }

    /// Get the description manager holding the cluster-root functions for this query.
    ///
    /// Java: `getDescriptionManager()`.
    pub fn get_description_manager(&self) -> &DescriptionManager {
        &self.manage
    }

    /// Get a partial clone of this query suitable for holding local stages via `StagingManager`.
    ///
    /// Java: `getLocalStagingCopy()`.
    pub fn get_local_staging_copy(&self) -> QueryCluster {
        let mut newc = QueryCluster::new();
        newc.thresh = self.thresh;
        newc.signifthresh = self.signifthresh;
        newc.vectormax = self.vectormax;
        newc
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
            spec_xml_utils::encode_signed_integer(self.vectormax as i64)
        )?;
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
        // This would normally parse the XML element using the parser:
        // parser.start(self.name);
        // self.manage.restore_xml(parser, vector_factory)?;
        // parser.start("simthresh");
        // self.thresh = parser.end().get_text().parse().unwrap();
        // parser.start("signifthresh");
        // self.signifthresh = parser.end().get_text().parse().unwrap();
        // parser.start("max");
        // self.vectormax = spec_xml_utils::decode_int(Some(parser.end().get_text()));
        // parser.end();
        Ok(())
    }
}

impl Default for QueryCluster {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_cluster_new_default_config() {
        let query = QueryCluster::new();
        assert_eq!(query.thresh, 0.9);
        assert_eq!(query.signifthresh, 0.0);
        assert_eq!(query.vectormax, 50);
        assert!(query.clusterresponse.is_none());
        assert_eq!(query.get_name(), "querycluster");
        assert_eq!(query.manage.num_executables(), 0);
        assert_eq!(query.manage.num_functions(), 0);
    }

    #[test]
    fn test_query_cluster_default() {
        let query = QueryCluster::default();
        assert_eq!(query.get_name(), "querycluster");
        assert_eq!(query.thresh, 0.9);
    }

    #[test]
    fn test_query_cluster_get_description_manager() {
        let query = QueryCluster::new();
        let manage = query.get_description_manager();
        assert_eq!(manage.num_executables(), 0);
    }

    #[test]
    fn test_query_cluster_get_local_staging_copy_carries_thresholds() {
        let mut query = QueryCluster::new();
        query.thresh = 0.75;
        query.signifthresh = 1.5;
        query.vectormax = 20;

        let copy = query.get_local_staging_copy();
        assert_eq!(copy.thresh, 0.75);
        assert_eq!(copy.signifthresh, 1.5);
        assert_eq!(copy.vectormax, 20);
        // The staging copy does not carry over the description manager's contents.
        assert_eq!(copy.manage.num_executables(), 0);
    }

    #[test]
    fn test_query_cluster_build_response_template() {
        let mut query = QueryCluster::new();
        assert!(query.clusterresponse.is_none());
        query.build_response_template();
        // Still none since ResponseCluster is not implemented yet.
        assert!(query.clusterresponse.is_none());
    }

    #[test]
    fn test_query_cluster_save_xml_matches_java_behavior() {
        let query = QueryCluster::new();
        let mut buffer = Vec::new();
        let result = query.save_xml(&mut buffer);
        assert!(result.is_ok());

        let xml_str = String::from_utf8(buffer).unwrap();
        assert_eq!(
            xml_str,
            "<querycluster>\n<description layout_version=\"5\">\n</description>\n<simthresh>0.9</simthresh>\n<signifthresh>0</signifthresh>\n<max>50</max>\n</querycluster>\n"
        );
    }
}
