//! Port of `ghidra.features.bsim.query.protocol.NullStaging`.
//!
//! A trivial `StagingManager` that performs no actual staging: a single "stage" covers the
//! entire query.

use crate::feature::bsim::query::description::DescriptionManager;
use crate::feature::bsim::query::protocol::{BSimQuery, StagingManager};
use crate::feature::bsim::query::LshException;

/// A trivial staging manager for queries that should not actually be split into stages: the
/// whole query is treated as a single stage.
///
/// Java: `NullStaging extends StagingManager`.
///
/// Java's `getQuery()` returns the `globalQuery` field set by `initialize`, i.e. the query it
/// was handed. The [`StagingManager`] trait's `initialize` only borrows that query for the
/// duration of the call (it isn't stored), so per the trait's documented convention this
/// implementation reports "the global query itself" via [`get_query`](Self::get_query)
/// returning `None`, and callers substitute the query they originally passed to `initialize`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct NullStaging {
    total_size: i32,
    queries_made: i32,
}

impl NullStaging {
    /// Java: `NullStaging()` (implicit default constructor).
    pub fn new() -> Self {
        Self::default()
    }
}

impl StagingManager for NullStaging {
    fn get_total_size(&self) -> i32 {
        self.total_size
    }

    fn get_queries_made(&self) -> i32 {
        self.queries_made
    }

    fn get_query(&mut self) -> Option<&mut (dyn BSimQuery + 'static)> {
        None // Java returns `globalQuery`, i.e. the query passed to `initialize`.
    }

    fn initialize(&mut self, query: &dyn BSimQuery) -> Result<bool, LshException> {
        self.total_size = 0;
        self.queries_made = 0;
        let Some(imanage) = query.get_description_manager() else {
            return Ok(true);
        };
        self.total_size = imanage.num_functions() as i32;
        Ok(self.total_size != 0) // Is there any data at all for an initial stage
    }

    fn next_stage(&mut self) -> Result<bool, LshException> {
        self.queries_made = self.total_size;
        Ok(false) // There is always only one stage
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::bsim::query::protocol::BSimQueryBase;
    use std::io::{self, Write};

    struct MockQuery {
        base: BSimQueryBase,
        manager: Option<DescriptionManager>,
    }

    impl MockQuery {
        fn with_functions(count: usize) -> Self {
            let mut manager = DescriptionManager::new();
            let erec = manager
                .new_executable_record(&format!("{:032x}", 0), "a.exe", "gcc", "x86:LE:32:default", 0, None, None, None)
                .unwrap();
            for i in 0..count {
                manager.new_function_description(&format!("func{i}"), i as i64, erec.clone());
            }
            Self { base: BSimQueryBase::new("mockquery"), manager: Some(manager) }
        }

        fn without_manager() -> Self {
            Self { base: BSimQueryBase::new("mockquery"), manager: None }
        }
    }

    impl BSimQuery for MockQuery {
        fn base(&self) -> &BSimQueryBase {
            &self.base
        }

        fn base_mut(&mut self) -> &mut BSimQueryBase {
            &mut self.base
        }

        fn save_xml(&self, _fwrite: &mut dyn Write) -> io::Result<()> {
            Ok(())
        }

        fn restore_xml(
            &mut self,
            _parser: &dyn crate::util::seam_stubs::XmlPullParser,
            _vector_factory: &dyn crate::feature::seam_stubs::LSHVectorFactory,
        ) -> Result<(), LshException> {
            Ok(())
        }

        fn get_description_manager(&self) -> Option<&DescriptionManager> {
            self.manager.as_ref()
        }
    }

    #[test]
    fn new_starts_at_zero() {
        let staging = NullStaging::new();
        assert_eq!(staging.get_total_size(), 0);
        assert_eq!(staging.get_queries_made(), 0);
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(NullStaging::default(), NullStaging::new());
    }

    #[test]
    fn initialize_with_no_description_manager_reports_a_stage() {
        // Java: `imanage == null` returns `true` unconditionally, even though `totalsize` stays 0.
        let mut staging = NullStaging::new();
        let query = MockQuery::without_manager();
        assert!(staging.initialize(&query).unwrap());
        assert_eq!(staging.get_total_size(), 0);
    }

    #[test]
    fn initialize_with_functions_reports_total_size() {
        let mut staging = NullStaging::new();
        let query = MockQuery::with_functions(5);
        let has_stage = staging.initialize(&query).unwrap();
        assert!(has_stage);
        assert_eq!(staging.get_total_size(), 5);
        assert_eq!(staging.get_queries_made(), 0);
    }

    #[test]
    fn initialize_with_empty_manager_reports_no_stage() {
        let mut staging = NullStaging::new();
        let query = MockQuery::with_functions(0);
        assert!(!staging.initialize(&query).unwrap());
    }

    #[test]
    fn next_stage_claims_everything_and_reports_done() {
        let mut staging = NullStaging::new();
        let query = MockQuery::with_functions(4);
        staging.initialize(&query).unwrap();
        assert!(!staging.next_stage().unwrap());
        assert_eq!(staging.get_queries_made(), 4);
    }

    #[test]
    fn get_query_means_the_global_query_by_convention() {
        let mut staging = NullStaging::new();
        assert!(staging.get_query().is_none());
    }

    #[test]
    fn trait_object_can_drive_the_whole_staging_protocol() {
        let mut staging: Box<dyn StagingManager> = Box::new(NullStaging::new());
        let query = MockQuery::with_functions(2);
        assert!(staging.initialize(&query).unwrap());
        assert_eq!(staging.get_total_size(), 2);
        assert!(!staging.next_stage().unwrap());
        assert_eq!(staging.get_queries_made(), 2);
    }
}
