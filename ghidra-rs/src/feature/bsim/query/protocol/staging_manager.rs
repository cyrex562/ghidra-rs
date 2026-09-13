//! Port of `ghidra.features.bsim.query.protocol.StagingManager`.
//!
//! Abstract class for splitting up a (presumably large) query into smaller pieces. The object
//! must be configured by a call to `setQuery` with details of the staged query and then
//! typically a call to `setGlobalManager` which specifies the data for the whole query.
//!
//! Placing the actual staged queries is accomplished by first calling `initialize`, which
//! establishes the first stage query, obtainable via `getQuery`. Successive stage queries are
//! built by calling `nextStage` repeatedly until it returns `false`.

use crate::feature::bsim::query::protocol::BSimQuery;
use crate::feature::bsim::query::LshException;

/// Splits up a (presumably large) query into smaller pieces.
///
/// Java's `StagingManager` is an abstract class holding `globalQuery`, `totalsize` and
/// `queriesmade`; the two counter accessors (`getTotalSize`/`getQueriesMade`) are concrete and
/// the rest (`getQuery`/`initialize`/`nextStage`) is abstract. Here the whole surface is a
/// trait, because that concrete state cannot be shared through a Rust supertype -- each
/// implementation carries its own `total_size`/`queries_made` fields and exposes them through
/// this trait's required methods.
///
/// Java's `getQuery()` hands back the query the manager is currently staging. A manager that
/// simply reuses the *global* query it was handed by `initialize` (as `NullStaging` does)
/// cannot hold that borrow in Rust, so implementations are free to return [`None`] from
/// [`get_query`](StagingManager::get_query) to mean "the global query itself", with callers
/// substituting the query they originally passed to `initialize`.
pub trait StagingManager: Send + Sync {
    /// Java: `getTotalSize()`, the total number of separate queries being staged.
    fn get_total_size(&self) -> i32;

    /// Java: `getQueriesMade()`, the number of queries sent so far.
    fn get_queries_made(&self) -> i32;

    /// Java: `getQuery()`, the current staged query.
    fn get_query(&mut self) -> Option<&mut (dyn BSimQuery + 'static)>;

    /// Java: `initialize(BSimQuery)`, establishing the first query stage. Returns `true` if an
    /// initial stage was constructed.
    fn initialize(&mut self, query: &dyn BSimQuery) -> Result<bool, LshException>;

    /// Java: `nextStage()`, establishing the next query stage. Returns `true` if one was built.
    fn next_stage(&mut self) -> Result<bool, LshException>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::bsim::query::description::DescriptionManager;
    use crate::feature::bsim::query::protocol::{
        BSimQueryBase, QueryResponseRecord, QueryResponseRecordBase,
    };
    use crate::feature::seam_stubs::LSHVectorFactory;
    use crate::util::seam_stubs::XmlPullParser;
    use std::io::{self, Write};

    /// A minimal `BSimQuery` carrying a `DescriptionManager`, enough to drive a staging
    /// manager's `initialize`/`nextStage` contract.
    struct MockQuery {
        base: BSimQueryBase,
        manager: DescriptionManager,
    }

    impl MockQuery {
        fn new(function_count: usize) -> Self {
            let mut manager = DescriptionManager::new();
            let erec = manager
                .new_executable_record(
                    &format!("{:032x}", 0),
                    "a.exe",
                    "gcc",
                    "x86:LE:32:default",
                    0,
                    None,
                    None,
                    None,
                )
                .unwrap();
            for i in 0..function_count {
                manager.new_function_description(&format!("func{i}"), i as i64, erec.clone());
            }
            Self { base: BSimQueryBase::new("mockquery"), manager }
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
            _parser: &dyn XmlPullParser,
            _vector_factory: &dyn LSHVectorFactory,
        ) -> Result<(), LshException> {
            Ok(())
        }

        fn get_description_manager(&self) -> Option<&DescriptionManager> {
            Some(&self.manager)
        }
    }

    struct MockResponse {
        base: QueryResponseRecordBase,
    }

    impl QueryResponseRecord for MockResponse {
        fn base(&self) -> &QueryResponseRecordBase {
            &self.base
        }

        fn save_xml(&self, _fwrite: &mut dyn Write) -> io::Result<()> {
            Ok(())
        }
    }

    /// A single-stage manager that claims the entire query's functions at once: `initialize`
    /// consumes every function, `next_stage` always reports there is nothing left. Exercises the
    /// trait's `Result`/`bool` contract with a real (non-null) implementation, complementing the
    /// `NullStaging`/`FunctionStaging` placeholders that already live in `feature::seam_stubs`.
    struct OneShotStaging {
        total_size: i32,
        queries_made: i32,
    }

    impl OneShotStaging {
        fn new() -> Self {
            Self { total_size: 0, queries_made: 0 }
        }
    }

    impl StagingManager for OneShotStaging {
        fn get_total_size(&self) -> i32 {
            self.total_size
        }

        fn get_queries_made(&self) -> i32 {
            self.queries_made
        }

        fn get_query(&mut self) -> Option<&mut (dyn BSimQuery + 'static)> {
            None // "the global query", per this trait's documented convention.
        }

        fn initialize(&mut self, query: &dyn BSimQuery) -> Result<bool, LshException> {
            let Some(manager) = query.get_description_manager() else {
                return Err(LshException::new("Query cannot be staged"));
            };
            self.total_size = manager.num_functions() as i32;
            self.queries_made = self.total_size;
            Ok(self.total_size != 0)
        }

        fn next_stage(&mut self) -> Result<bool, LshException> {
            Ok(false) // Always a single stage.
        }
    }

    #[test]
    fn initialize_claims_every_function_in_one_stage() {
        let mut staging = OneShotStaging::new();
        let query = MockQuery::new(7);

        let has_stage = staging.initialize(&query).unwrap();

        assert!(has_stage);
        assert_eq!(staging.get_total_size(), 7);
        assert_eq!(staging.get_queries_made(), 7);
    }

    #[test]
    fn initialize_on_empty_query_reports_no_stage() {
        let mut staging = OneShotStaging::new();
        let query = MockQuery::new(0);

        let has_stage = staging.initialize(&query).unwrap();

        assert!(!has_stage);
        assert_eq!(staging.get_total_size(), 0);
    }

    #[test]
    fn next_stage_after_initialize_reports_done() {
        let mut staging = OneShotStaging::new();
        let query = MockQuery::new(3);
        staging.initialize(&query).unwrap();

        assert!(!staging.next_stage().unwrap());
    }

    #[test]
    fn get_query_means_the_global_query_by_convention() {
        let mut staging = OneShotStaging::new();
        assert!(staging.get_query().is_none());
    }

    #[test]
    fn trait_object_can_drive_the_whole_staging_protocol() {
        // Confirms the trait is object-safe and usable exactly the way
        // `SimilarFunctionQueryService` uses it: behind `Box<dyn StagingManager>`.
        let mut staging: Box<dyn StagingManager> = Box::new(OneShotStaging::new());
        let query = MockQuery::new(2);

        assert!(staging.initialize(&query).unwrap());
        assert_eq!(staging.get_total_size(), 2);
        assert!(!staging.next_stage().unwrap());
    }

    #[test]
    fn response_bookkeeping_is_independent_of_staging() {
        // Sanity check that a query carried through staging can still separately accumulate a
        // response, matching how `SimilarFunctionQueryService` drives both in tandem.
        let mut query = MockQuery::new(1);
        query
            .base_mut()
            .set_response(Box::new(MockResponse { base: QueryResponseRecordBase::new("r") }));
        assert!(query.get_response().is_some());
    }
}
