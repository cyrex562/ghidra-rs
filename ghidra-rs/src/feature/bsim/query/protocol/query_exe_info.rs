//! Port of `ghidra.features.bsim.query.protocol.QueryExeInfo`.
//!
//! Query of executable records.

use std::io::{self, Write};

use crate::feature::bsim::query::lsh_exception::LshException;
use crate::feature::bsim::query::protocol::{BSimQuery, BSimQueryBase, ResponseExe};
use crate::feature::seam_stubs::LSHVectorFactory;
use crate::util::seam_stubs::XmlPullParser;

/// Ordering column for executable queries.
///
/// Port of the nested enum `ghidra.features.bsim.query.client.tables.ExeTable.ExeTableOrderColumn`.
/// `ExeTable` itself has not been ported yet; this enum is small enough to port directly here
/// rather than gate `QueryExeInfo` on that larger class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExeTableOrderColumn {
    Md5,
    Name,
}

/// Query of executable records.
///
/// Java: `QueryExeInfo extends BSimQuery<ResponseExe>`.
pub struct QueryExeInfo {
    /// The response object (same as `response` in the parent `BSimQuery`).
    pub exeresponse: Option<ResponseExe>,
    /// The max number of results to return.
    pub limit: i32,
    /// MD5 filter.
    pub filter_md5: Option<String>,
    /// Executable name filter.
    pub filter_exe_name: Option<String>,
    /// Architecture filter.
    pub filter_arch: Option<String>,
    /// Compiler name filter.
    pub filter_compiler_name: Option<String>,
    /// Primary sort column.
    pub sort_column: ExeTableOrderColumn,
    /// If false, excludes generated MD5s starting with "bbbbbbbbaaaaaaaa".
    pub include_fakes: bool,
    /// Query for categories of any returned executable.
    pub fillin_categories: bool,

    base: BSimQueryBase,
}

impl QueryExeInfo {
    /// Default query for the first 20 executables in the database.
    ///
    /// Java: `QueryExeInfo()`.
    pub fn new() -> Self {
        Self {
            exeresponse: None,
            limit: 20,
            filter_md5: None,
            filter_exe_name: None,
            filter_arch: None,
            filter_compiler_name: None,
            sort_column: ExeTableOrderColumn::Md5,
            include_fakes: false,
            fillin_categories: true,
            base: BSimQueryBase::new("queryexeinfo"),
        }
    }

    /// Java: `QueryExeInfo(int, String, String, String, String, ExeTableOrderColumn, boolean)`.
    ///
    /// Note this faithfully reproduces a quirk in the Java source: unlike [`new`](Self::new),
    /// this constructor does not chain to the no-arg constructor and never assigns
    /// `fillinCategories`, so it keeps Java's implicit field default of `false` instead of the
    /// `true` the default constructor explicitly sets. `fillin_categories` is `false` here for
    /// the same reason.
    #[allow(clippy::too_many_arguments)]
    pub fn with_filters(
        limit: i32,
        filter_md5: Option<String>,
        filter_exe_name: Option<String>,
        filter_arch: Option<String>,
        filter_compiler_name: Option<String>,
        sort_column: ExeTableOrderColumn,
        include_fakes: bool,
    ) -> Self {
        Self {
            exeresponse: None,
            limit,
            filter_md5,
            filter_exe_name,
            filter_arch,
            filter_compiler_name,
            sort_column,
            include_fakes,
            fillin_categories: false,
            base: BSimQueryBase::new("queryexeinfo"),
        }
    }

    /// Java: `getName()` (inherited from `BSimQuery`).
    pub fn get_name(&self) -> &str {
        self.base.get_name()
    }

    /// Build the response template for this query.
    ///
    /// Java: `buildResponseTemplate()`.
    pub fn build_response_template(&mut self) {
        if self.exeresponse.is_none() {
            self.exeresponse = Some(ResponseExe::new());
        }
    }

    /// Java: `saveXml(Writer)`. Empty in the real Java source ("no need to implement").
    pub fn save_xml(&self, _fwrite: &mut dyn Write) -> io::Result<()> {
        Ok(())
    }

    /// Java: `restoreXml(XmlPullParser, LSHVectorFactory)`. Empty in the real Java source ("no
    /// need to implement").
    pub fn restore_xml(
        &mut self,
        _parser: &dyn XmlPullParser,
        _vector_factory: &dyn LSHVectorFactory,
    ) -> Result<(), LshException> {
        Ok(())
    }
}

impl Default for QueryExeInfo {
    fn default() -> Self {
        Self::new()
    }
}

/// Java: `QueryExeInfo extends BSimQuery<ResponseExe>`. Each method forwards to the inherent one
/// of the same name, which is where the behaviour lives.
impl BSimQuery for QueryExeInfo {
    fn base(&self) -> &BSimQueryBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut BSimQueryBase {
        &mut self.base
    }

    fn build_response_template(&mut self) {
        QueryExeInfo::build_response_template(self)
    }

    fn save_xml(&self, fwrite: &mut dyn Write) -> io::Result<()> {
        QueryExeInfo::save_xml(self, fwrite)
    }

    fn restore_xml(
        &mut self,
        parser: &dyn XmlPullParser,
        vector_factory: &dyn LSHVectorFactory,
    ) -> Result<(), LshException> {
        QueryExeInfo::restore_xml(self, parser, vector_factory)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        fn build_vector(&self, _feature: &[i32]) -> Box<dyn crate::feature::seam_stubs::LSHVector> {
            unimplemented!()
        }
        fn restore_vector_from_xml(&self, _parser: &dyn XmlPullParser) -> Box<dyn crate::feature::seam_stubs::LSHVector> {
            unimplemented!()
        }
        fn restore_vector_from_sql(&self, _sql: &str) -> std::io::Result<Box<dyn crate::feature::seam_stubs::LSHVector>> {
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
        fn get_self_significance(&self, _vector: &dyn crate::feature::seam_stubs::LSHVector) -> f64 {
            0.0
        }
        fn calculate_significance(&self, _data: &dyn crate::feature::seam_stubs::VectorCompare) -> f64 {
            0.0
        }
        fn read_weights(&self, _parser: &dyn XmlPullParser) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn new_default_config() {
        let query = QueryExeInfo::new();
        assert_eq!(query.get_name(), "queryexeinfo");
        assert_eq!(query.limit, 20);
        assert!(query.filter_md5.is_none());
        assert!(query.filter_exe_name.is_none());
        assert!(query.filter_arch.is_none());
        assert!(query.filter_compiler_name.is_none());
        assert_eq!(query.sort_column, ExeTableOrderColumn::Md5);
        assert!(!query.include_fakes);
        assert!(query.fillin_categories);
        assert!(query.exeresponse.is_none());
    }

    #[test]
    fn default_matches_new() {
        let query = QueryExeInfo::default();
        assert_eq!(query.limit, 20);
        assert!(query.fillin_categories);
    }

    #[test]
    fn with_filters_carries_all_fields() {
        let query = QueryExeInfo::with_filters(
            50,
            Some("deadbeef".to_string()),
            Some("libfoo.so".to_string()),
            Some("x86:LE:64".to_string()),
            Some("gcc".to_string()),
            ExeTableOrderColumn::Name,
            true,
        );
        assert_eq!(query.limit, 50);
        assert_eq!(query.filter_md5.as_deref(), Some("deadbeef"));
        assert_eq!(query.filter_exe_name.as_deref(), Some("libfoo.so"));
        assert_eq!(query.filter_arch.as_deref(), Some("x86:LE:64"));
        assert_eq!(query.filter_compiler_name.as_deref(), Some("gcc"));
        assert_eq!(query.sort_column, ExeTableOrderColumn::Name);
        assert!(query.include_fakes);
    }

    #[test]
    fn with_filters_leaves_fillin_categories_false_unlike_default_ctor() {
        // Faithful reproduction of the Java quirk: the parameterized constructor never assigns
        // fillinCategories, so it keeps Java's implicit `false` default instead of the `true`
        // the no-arg constructor explicitly sets.
        let query = QueryExeInfo::with_filters(20, None, None, None, None, ExeTableOrderColumn::Md5, false);
        assert!(!query.fillin_categories);

        let default_query = QueryExeInfo::new();
        assert!(default_query.fillin_categories);
    }

    #[test]
    fn build_response_template_populates_response_once() {
        let mut query = QueryExeInfo::new();
        query.build_response_template();
        assert!(query.exeresponse.is_some());
        query.exeresponse.as_mut().unwrap().record_count = 7;
        query.build_response_template();
        assert_eq!(query.exeresponse.as_ref().unwrap().record_count, 7);
    }

    #[test]
    fn save_xml_is_a_no_op() {
        let query = QueryExeInfo::new();
        let mut buf = Vec::new();
        query.save_xml(&mut buf).unwrap();
        assert!(buf.is_empty());
    }

    #[test]
    fn restore_xml_is_a_no_op() {
        let mut query = QueryExeInfo::new();
        let result = query.restore_xml(&DummyParser, &DummyVectorFactory);
        assert!(result.is_ok());
    }

    #[test]
    fn bsim_query_trait_delegates_to_inherent_methods() {
        let mut query = QueryExeInfo::new();
        assert_eq!(BSimQuery::get_name(&query), "queryexeinfo");
        BSimQuery::build_response_template(&mut query);
        assert!(query.exeresponse.is_some());
    }
}
