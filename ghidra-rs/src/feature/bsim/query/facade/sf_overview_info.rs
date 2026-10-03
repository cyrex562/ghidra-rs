//! Port of `ghidra.features.bsim.query.facade.SFOverviewInfo`.
//!
//! # Relationship to `crate::feature::seam_stubs::SFOverviewInfo`
//!
//! A separate, unrelated placeholder trait of the same name already exists at
//! `crate::feature::seam_stubs::SFOverviewInfo`, used by
//! [`SimilarFunctionQueryService`](crate::feature::bsim::query::facade::SimilarFunctionQueryService)'s
//! `overview_similar_functions`/`generate_query_nearest_vector`. That trait fixes
//! `get_functions()` to return `Vec<Box<dyn FunctionSymbol>>` (freshly-owned boxes per call),
//! which this struct cannot satisfy without a `FunctionSymbol`-cloning capability that does not
//! exist yet (this struct instead stores `Arc<dyn FunctionSymbol>` handles, matching Java's
//! reference-counted `Set<FunctionSymbol>`, and hands out borrowed/cloned `Arc`s rather than
//! fresh `Box`es). Wiring this concrete port into that seam is therefore left as a follow-up once
//! `FunctionSymbol` supports cloning (or the seam trait is adjusted to `Arc`), matching this
//! port's own module docs elsewhere in the project for this exact kind of situation.

use std::sync::Arc;

use crate::feature::bsim::query::protocol::{PreFilter, QueryNearestVector};
use crate::program::database::symbol::FunctionSymbol;
use crate::program::model::listing::Program;

/// Default number of separate function queries to make at one time.
pub const DEFAULT_QUERIES_PER_STAGE: i32 = 10;

/// Parameters for a BSim "overview" query: for a set of functions (all from the same program),
/// find the list of vectors similar to each function's vector.
///
/// Port of `ghidra.features.bsim.query.facade.SFOverviewInfo`.
pub struct SFOverviewInfo {
    functions: Vec<Arc<dyn FunctionSymbol>>,
    program: Option<Arc<dyn Program>>,
    query_nearest_vector: QueryNearestVector,
    pre_filter: PreFilter,
}

impl SFOverviewInfo {
    /// Constructs an overview request with default parameters.
    ///
    /// `functions` is required -- a set of functions (at least one) for which an overview will be
    /// computed. All functions must be from the same program.
    ///
    /// # Panics
    ///
    /// Panics if `functions` is empty, or if the functions are not all from the same program.
    /// Java: `IllegalArgumentException`, an unchecked exception with no direct `Result`-typed
    /// equivalent in this port's constructors (see e.g. `Handle`/`EnumDataType`'s own docs
    /// elsewhere in this crate for the same convention).
    pub fn new(functions: Vec<Arc<dyn FunctionSymbol>>) -> Self {
        if functions.is_empty() {
            panic!("Function list cannot be empty");
        }

        // Java: `if (program == null) { program = s.getProgram(); } else if (program !=
        // s.getProgram()) { throw ...; }`. The first branch fires whenever the *field* is still
        // null, regardless of whether `s.getProgram()` itself is null -- so if the first
        // function(s) report no program, `program` simply stays null rather than raising an
        // error, and only once it becomes non-null do later mismatches actually throw. Faithfully
        // reproduced below rather than "fixed" into an early-null-rejects-everything check.
        let mut program: Option<Arc<dyn Program>> = None;
        let mut program_seen = false;
        for s in &functions {
            let p = s.get_program();
            if !program_seen {
                program = p;
                program_seen = true;
            } else {
                let equal = match (&program, &p) {
                    (Some(existing), Some(candidate)) => Arc::ptr_eq(existing, candidate),
                    (None, None) => true,
                    _ => false,
                };
                if !equal {
                    panic!("all function symbols are not from the same program");
                }
            }
        }

        SFOverviewInfo {
            functions,
            program,
            query_nearest_vector: QueryNearestVector::new(),
            pre_filter: PreFilter::new(),
        }
    }

    /// The program from which all queried functions are from (or `None`, in the faithfully
    /// preserved edge case described in [`new`](Self::new) where every function reported no
    /// program).
    ///
    /// Java: `getProgram()`.
    pub fn get_program(&self) -> Option<Arc<dyn Program>> {
        self.program.clone()
    }

    /// Java: `getSimilarityThreshold()`.
    pub fn get_similarity_threshold(&self) -> f64 {
        self.query_nearest_vector.thresh
    }

    /// Java: `setSimilarityThreshold(double)`.
    pub fn set_similarity_threshold(&mut self, similarity_threshold: f64) {
        self.query_nearest_vector.thresh = similarity_threshold;
    }

    /// Java: `getSignificanceThreshold()`.
    pub fn get_significance_threshold(&self) -> f64 {
        self.query_nearest_vector.signifthresh
    }

    /// Java: `setSignificanceThreshold(double)`.
    pub fn set_significance_threshold(&mut self, significance_threshold: f64) {
        self.query_nearest_vector.signifthresh = significance_threshold;
    }

    /// Java: `getVectorMax()`.
    pub fn get_vector_max(&self) -> i32 {
        self.query_nearest_vector.vectormax
    }

    /// Java: `setVectorMax(int)`.
    pub fn set_vector_max(&mut self, max: i32) {
        self.query_nearest_vector.vectormax = max;
    }

    /// Returns the shared [`QueryNearestVector`], mirroring Java's `buildQueryNearestVector()`,
    /// which hands out the same live object it configures via
    /// [`set_similarity_threshold`](Self::set_similarity_threshold) etc.
    ///
    /// Java: `buildQueryNearestVector()`.
    pub fn build_query_nearest_vector(&self) -> &QueryNearestVector {
        &self.query_nearest_vector
    }

    /// Java: `getFunctions()`.
    pub fn get_functions(&self) -> &[Arc<dyn FunctionSymbol>] {
        &self.functions
    }

    /// Java: `getNumberOfStages(int queries_per_stage)`.
    pub fn get_number_of_stages(&self, queries_per_stage: i32) -> i32 {
        if self.functions.is_empty() {
            return 1;
        }
        let queries_per_stage =
            if queries_per_stage == 0 { DEFAULT_QUERIES_PER_STAGE } else { queries_per_stage };
        (self.functions.len() as i32 + (queries_per_stage - 1)) / queries_per_stage
    }

    /// Java: `getPreFilter()`.
    pub fn get_pre_filter(&self) -> &PreFilter {
        &self.pre_filter
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::Address;
    use crate::program::model::symbol::{Symbol, SymbolType, SourceType};

    struct MockProgram {
        name: &'static str,
    }
    impl DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            self.name.to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    struct MockFunctionSymbol {
        name: String,
        program: Option<Arc<dyn Program>>,
    }

    impl Symbol for MockFunctionSymbol {
        fn get_address(&self) -> Address {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Function
        }
        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            0
        }
        fn get_parent_id(&self) -> i64 {
            0
        }
        fn get_program(&self) -> Option<Arc<dyn Program>> {
            self.program.clone()
        }
    }

    impl FunctionSymbol for MockFunctionSymbol {
        fn set_name_and_namespace(
            &mut self,
            _new_name: &str,
            _new_namespace: Arc<dyn crate::program::model::symbol::Namespace>,
            _source: SourceType,
        ) -> Result<(), crate::program::model::symbol::SetParentNamespaceError> {
            unimplemented!("not exercised by this smoke test")
        }
        fn delete(&mut self) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_object(&self) -> Option<Arc<dyn crate::program::model::listing::Function>> {
            None
        }
        fn get_program_location(
            &self,
        ) -> Option<Box<dyn crate::program::util::ProgramLocation>> {
            None
        }
        fn is_valid_parent(&self, _parent: &dyn crate::program::model::symbol::Namespace) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_thunked_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }
        fn thunk_symbols(&self) -> Vec<Arc<dyn Symbol>> {
            Vec::new()
        }
        fn validate_name_source(
            &self,
            _new_name: Option<&str>,
            source: SourceType,
        ) -> SourceType {
            source
        }
        fn base_reference_count(&self) -> i32 {
            0
        }
        fn base_has_references(&self) -> bool {
            false
        }
        fn base_references(
            &self,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Vec<Arc<dyn crate::program::model::symbol::Reference>> {
            Vec::new()
        }
    }

    fn func(name: &str, program: &Arc<dyn Program>) -> Arc<dyn FunctionSymbol> {
        Arc::new(MockFunctionSymbol { name: name.to_string(), program: Some(Arc::clone(program)) })
    }

    #[test]
    #[should_panic(expected = "Function list cannot be empty")]
    fn new_panics_on_empty_functions() {
        SFOverviewInfo::new(Vec::new());
    }

    #[test]
    fn new_records_shared_program_and_defaults() {
        let program: Arc<dyn Program> = Arc::new(MockProgram { name: "prog" });
        let info = SFOverviewInfo::new(vec![func("a", &program), func("b", &program)]);
        assert!(Arc::ptr_eq(&info.get_program().unwrap(), &program));
        assert_eq!(info.get_functions().len(), 2);
        // Defaults come from QueryNearestVector::new()/PreFilter::new().
        assert_eq!(info.get_vector_max(), 0);
    }

    #[test]
    #[should_panic(expected = "all function symbols are not from the same program")]
    fn new_panics_on_mismatched_programs() {
        let program_a: Arc<dyn Program> = Arc::new(MockProgram { name: "a" });
        let program_b: Arc<dyn Program> = Arc::new(MockProgram { name: "b" });
        SFOverviewInfo::new(vec![func("a", &program_a), func("b", &program_b)]);
    }

    #[test]
    fn new_with_all_programless_functions_leaves_program_none() {
        // Faithfully reproduced Java quirk: when every function's getProgram() returns null, the
        // `program == null` check in the constructor loop keeps taking the "assign" branch on
        // every iteration (never the "compare" branch), so no exception is thrown and the field
        // stays null.
        let a: Arc<dyn FunctionSymbol> =
            Arc::new(MockFunctionSymbol { name: "a".to_string(), program: None });
        let b: Arc<dyn FunctionSymbol> =
            Arc::new(MockFunctionSymbol { name: "b".to_string(), program: None });
        let info = SFOverviewInfo::new(vec![a, b]);
        assert!(info.get_program().is_none());
    }

    #[test]
    fn similarity_and_significance_thresholds_round_trip_through_query_nearest_vector() {
        let program: Arc<dyn Program> = Arc::new(MockProgram { name: "prog" });
        let mut info = SFOverviewInfo::new(vec![func("a", &program)]);

        info.set_similarity_threshold(0.85);
        info.set_significance_threshold(2.5);
        info.set_vector_max(7);

        assert_eq!(info.get_similarity_threshold(), 0.85);
        assert_eq!(info.get_significance_threshold(), 2.5);
        assert_eq!(info.get_vector_max(), 7);

        let built = info.build_query_nearest_vector();
        assert_eq!(built.thresh, 0.85);
        assert_eq!(built.signifthresh, 2.5);
        assert_eq!(built.vectormax, 7);
    }

    #[test]
    fn get_number_of_stages_uses_default_when_zero_and_ceils() {
        let program: Arc<dyn Program> = Arc::new(MockProgram { name: "prog" });
        let functions: Vec<_> = (0..25).map(|i| func(&format!("f{i}"), &program)).collect();
        let info = SFOverviewInfo::new(functions);

        // Java: queries_per_stage == 0 -> DEFAULT_QUERIES_PER_STAGE (10); ceil(25/10) == 3.
        assert_eq!(info.get_number_of_stages(0), 3);
        // Explicit queries_per_stage: ceil(25/5) == 5.
        assert_eq!(info.get_number_of_stages(5), 5);
        // Exact division: ceil(25/25) == 1.
        assert_eq!(info.get_number_of_stages(25), 1);
    }

    #[test]
    fn get_pre_filter_returns_a_usable_default() {
        use crate::feature::bsim::query::description::FunctionDescription;
        use crate::feature::seam_stubs::ExecutableRecord;

        let program: Arc<dyn Program> = Arc::new(MockProgram { name: "prog" });
        let info = SFOverviewInfo::new(vec![func("a", &program)]);

        // A freshly-built PreFilter with no registered predicates is vacuously "and"-true.
        let predicate = info.get_pre_filter().get_and_reduced_predicate();
        let exerec = Arc::new(ExecutableRecord::new("aa", "a.exe", "x86:LE:32:default", "gcc"));
        let function = FunctionDescription::new(exerec, "foo", 0x1000);
        assert!(predicate(program.as_ref(), &function));
    }
}
