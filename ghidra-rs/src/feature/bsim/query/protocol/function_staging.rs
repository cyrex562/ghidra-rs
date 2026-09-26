//! Port of `ghidra.features.bsim.query.protocol.FunctionStaging`.
//!
//! Splits a query into stages of at most `stagesize` functions apiece.

use crate::feature::bsim::query::protocol::{BSimQuery, StagingManager};
use crate::feature::bsim::query::LshException;

/// Splits a query's functions into stages of at most `stage_size` apiece.
///
/// Java: `FunctionStaging extends StagingManager`.
///
/// Java's `initialize`/`nextStage` populate a private `DescriptionManager imanage` (obtained
/// from `localQuery.getDescriptionManager()`) with each stage's slice of functions, via
/// `imanage.clear()` + `imanage.transferSettings(gmanage)` + repeated
/// `imanage.transferFunction(...)`. [`BSimQuery::get_description_manager`] only exposes a
/// shared reference (`Option<&DescriptionManager>`), not a mutable one, so this port cannot
/// reach into `local_query`'s manager to perform that transfer -- doing so would require adding
/// a `get_description_manager_mut` to the `BSimQuery` trait and having every staged query type
/// override it, which is out of scope here. The stage *accounting* (`total_size`,
/// `queries_made`, and how many functions each stage claims) is ported exactly and is fully
/// observable/testable through the [`StagingManager`] trait; only the side effect of actually
/// populating the local query's manager with that stage's functions is elided.
pub struct FunctionStaging {
    stage_size: i32,
    total_size: i32,
    queries_made: i32,
    local_query: Option<Box<dyn BSimQuery>>,
}

impl FunctionStaging {
    /// Java: `FunctionStaging(int stagesize)`.
    pub fn new(stage_size: i32) -> Self {
        Self { stage_size, total_size: 0, queries_made: 0, local_query: None }
    }

    /// The number of functions each stage claims.
    pub fn get_stage_size(&self) -> i32 {
        self.stage_size
    }

    /// Claim up to `stage_size` more functions, as Java's transfer loop does, and report how
    /// many were claimed.
    fn claim_stage(&mut self) -> i32 {
        let count = (self.total_size - self.queries_made).clamp(0, self.stage_size);
        self.queries_made += count;
        count
    }
}

impl StagingManager for FunctionStaging {
    fn get_total_size(&self) -> i32 {
        self.total_size
    }

    fn get_queries_made(&self) -> i32 {
        self.queries_made
    }

    fn get_query(&mut self) -> Option<&mut (dyn BSimQuery + 'static)> {
        self.local_query.as_deref_mut()
    }

    fn initialize(&mut self, query: &dyn BSimQuery) -> Result<bool, LshException> {
        let Some(gmanage) = query.get_description_manager() else {
            return Err(LshException::new("Query cannot be function staged"));
        };
        self.total_size = gmanage.num_functions() as i32;
        self.queries_made = 0;
        self.local_query = query.get_local_staging_copy();
        Ok(self.claim_stage() != 0)
    }

    fn next_stage(&mut self) -> Result<bool, LshException> {
        Ok(self.claim_stage() != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::bsim::query::description::DescriptionManager;
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

        fn get_local_staging_copy(&self) -> Option<Box<dyn BSimQuery>> {
            Some(Box::new(MockQuery { base: BSimQueryBase::new(self.base.get_name()), manager: None }))
        }
    }

    #[test]
    fn new_stores_stage_size() {
        let staging = FunctionStaging::new(10);
        assert_eq!(staging.get_stage_size(), 10);
        assert_eq!(staging.get_total_size(), 0);
        assert_eq!(staging.get_queries_made(), 0);
    }

    #[test]
    fn initialize_errors_without_description_manager() {
        // Java: `if (gmanage == null) throw new LSHException(...)`.
        let mut staging = FunctionStaging::new(5);
        let query = MockQuery::without_manager();
        assert!(staging.initialize(&query).is_err());
    }

    #[test]
    fn initialize_claims_at_most_one_stage_worth() {
        let mut staging = FunctionStaging::new(3);
        let query = MockQuery::with_functions(10);
        let has_stage = staging.initialize(&query).unwrap();
        assert!(has_stage);
        assert_eq!(staging.get_total_size(), 10);
        assert_eq!(staging.get_queries_made(), 3);
    }

    #[test]
    fn initialize_on_empty_query_reports_no_stage() {
        let mut staging = FunctionStaging::new(3);
        let query = MockQuery::with_functions(0);
        assert!(!staging.initialize(&query).unwrap());
        assert_eq!(staging.get_queries_made(), 0);
    }

    #[test]
    fn initialize_populates_local_query_from_get_local_staging_copy() {
        let mut staging = FunctionStaging::new(3);
        let query = MockQuery::with_functions(5);
        staging.initialize(&query).unwrap();
        assert!(staging.get_query().is_some());
    }

    #[test]
    fn next_stage_claims_remaining_functions_across_multiple_calls() {
        let mut staging = FunctionStaging::new(4);
        let query = MockQuery::with_functions(10);
        assert!(staging.initialize(&query).unwrap()); // claims 4 -> queries_made = 4
        assert_eq!(staging.get_queries_made(), 4);
        assert!(staging.next_stage().unwrap()); // claims 4 more -> queries_made = 8
        assert_eq!(staging.get_queries_made(), 8);
        assert!(staging.next_stage().unwrap()); // claims final 2 -> queries_made = 10
        assert_eq!(staging.get_queries_made(), 10);
        assert!(!staging.next_stage().unwrap()); // nothing left
        assert_eq!(staging.get_queries_made(), 10);
    }

    #[test]
    fn stage_size_evenly_dividing_total_ends_cleanly() {
        let mut staging = FunctionStaging::new(5);
        let query = MockQuery::with_functions(10);
        assert!(staging.initialize(&query).unwrap());
        assert!(staging.next_stage().unwrap());
        assert_eq!(staging.get_queries_made(), 10);
        assert!(!staging.next_stage().unwrap());
    }

    #[test]
    fn trait_object_can_drive_the_whole_staging_protocol() {
        let mut staging: Box<dyn StagingManager> = Box::new(FunctionStaging::new(2));
        let query = MockQuery::with_functions(3);
        assert!(staging.initialize(&query).unwrap());
        assert_eq!(staging.get_queries_made(), 2);
        assert!(staging.next_stage().unwrap());
        assert_eq!(staging.get_queries_made(), 3);
        assert!(!staging.next_stage().unwrap());
    }
}
