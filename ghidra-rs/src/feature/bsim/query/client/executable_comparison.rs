//! Port of `ghidra.features.bsim.query.client.ExecutableComparison`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use crate::feature::bsim::query::client::ScoreCaching;
use crate::feature::bsim::query::description::{DatabaseInformation, DescriptionManager};
use crate::feature::bsim::query::LshException;
use crate::feature::bsim::query::function_database::FunctionDatabase;
use crate::feature::seam_stubs::{ExecutableRecord, ExecutableScorer, VectorResult};
use crate::generic::seam_stubs::LSHVectorFactory;
use crate::util::exception::CancelledException;
use crate::util::task::{DummyMonitor, TaskMonitor};

/// Java: `QueryName.maxfunc` used by `pullVectorsForExe`.
///
/// TODO (from the Java): more of an effort is needed to collect all vectors for large
/// executables, which requires a change to the `QueryName` API to allow a window to be specified.
const MAX_FUNCTIONS_PER_EXE: i32 = 100_000;

/// Mutable integer class for histogram.
///
/// Java: `ExecutableComparison.Count`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Count {
    pub value: i32,
}

/// The two exceptions `performScoring` and `fillinSelfScores` throw in Java.
#[derive(Debug)]
pub enum ComparisonError {
    Lsh(LshException),
    Cancelled(CancelledException),
}

impl fmt::Display for ComparisonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ComparisonError::Lsh(e) => write!(f, "{}", e),
            ComparisonError::Cancelled(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for ComparisonError {}

impl From<LshException> for ComparisonError {
    fn from(e: LshException) -> Self {
        ComparisonError::Lsh(e)
    }
}

impl From<CancelledException> for ComparisonError {
    fn from(e: CancelledException) -> Self {
        ComparisonError::Cancelled(e)
    }
}

/// Compare an entire set of executables to each other by combining significance scores between
/// functions. If individual functions demonstrate multiple similarities, its score contributions
/// are not over counted, and the final scores are symmetric. Scoring is efficient because it
/// iterates over the precomputed clusters of similar functions in a BSim database. The algorithm
/// does divide and conquer based on clusters of similar functions, which greatly improves
/// efficiency over full quadratic comparison of all functions. This can be further bounded by
/// putting a threshold on how close functions have to be to be considered in the same cluster and
/// on how many functions can be in a cluster before ignoring their score contributions.
pub struct ExecutableComparison {
    /// Connection to the database.
    database: Arc<dyn FunctionDatabase>,
    /// The scoring matrix and mapping to executables.
    scorer: ExecutableScorer,
    single_md5: Option<String>,
    /// Set of relevant vector ids. Java releases the set by nulling it after `performScoring`;
    /// here it is emptied instead.
    base_ids: BTreeSet<i64>,
    /// Set of vector ids that have already been queried.
    queried_ids: BTreeSet<i64>,
    /// Factory for computing significance scores.
    vector_factory: Arc<LSHVectorFactory>,
    /// Threshold for functions within a single cluster.
    hit_count_threshold: i32,
    /// Maximum hitcount seen (after `perform_scoring`).
    max_hit_count: i32,
    /// Number of times `hit_count_threshold` was exceeded.
    exceed_count: i32,
    /// Monitor for long running jobs.
    monitor: Arc<dyn TaskMonitor>,
}

impl ExecutableComparison {
    /// Initialize a comparison object with an active connection and thresholds, using the matrix
    /// scorer, which compares everybody to everybody.
    ///
    /// # Arguments
    ///
    /// * `database` - the active connection to a BSim database
    /// * `hit_count_threshold` - the maximum number of functions to consider in one cluster
    /// * `monitor` - a monitor to provide progress and cancellation checks, or `None` for the
    ///   dummy monitor
    ///
    /// # Errors
    ///
    /// Returns `LshException` if the database connection is not established.
    pub fn new(
        database: Arc<dyn FunctionDatabase>,
        hit_count_threshold: i32,
        monitor: Option<Arc<dyn TaskMonitor>>,
    ) -> Result<Self, LshException> {
        let (info, vector_factory) = pull_connection_info(database.as_ref())?;
        // The matrix scorer, everybody compared to everybody.
        let mut scorer = ExecutableScorer::new();
        scorer.transfer_settings(&info);
        Ok(Self::assemble(
            database,
            scorer,
            None,
            vector_factory,
            hit_count_threshold,
            monitor,
        ))
    }

    /// Initialize a comparison object with an active connection and thresholds, using the row
    /// scorer, which compares a single executable to everybody else.
    ///
    /// # Arguments
    ///
    /// * `database` - the active connection to a BSim database
    /// * `hit_count_threshold` - the maximum number of functions to consider in one cluster
    /// * `md5` - the 32-character md5 string of the executable to single out for comparison
    /// * `cache` - holds the self-scores, or `None` if normalized scores aren't needed
    /// * `monitor` - a monitor to provide progress and cancellation checks, or `None` for the
    ///   dummy monitor
    ///
    /// # Errors
    ///
    /// Returns `LshException` if the database connection is not established, or the singled out
    /// executable is not in the database.
    pub fn new_single(
        database: Arc<dyn FunctionDatabase>,
        hit_count_threshold: i32,
        md5: &str,
        cache: Option<Box<dyn ScoreCaching>>,
        monitor: Option<Arc<dyn TaskMonitor>>,
    ) -> Result<Self, LshException> {
        let (info, vector_factory) = pull_connection_info(database.as_ref())?;
        // The row scorer, compare single exe to everybody else.
        let mut scorer = ExecutableScorer::new_single(cache)?;
        scorer.transfer_settings(&info);
        let mut comparison = Self::assemble(
            database,
            scorer,
            Some(md5.to_string()),
            vector_factory,
            hit_count_threshold,
            monitor,
        );
        comparison.add_executable(md5)?;
        Ok(comparison)
    }

    /// The part of both constructors that just fills in fields.
    fn assemble(
        database: Arc<dyn FunctionDatabase>,
        scorer: ExecutableScorer,
        single_md5: Option<String>,
        vector_factory: Arc<LSHVectorFactory>,
        hit_count_threshold: i32,
        monitor: Option<Arc<dyn TaskMonitor>>,
    ) -> Self {
        Self {
            database,
            scorer,
            single_md5,
            base_ids: BTreeSet::new(),
            queried_ids: BTreeSet::new(),
            vector_factory,
            hit_count_threshold,
            max_hit_count: 0,
            exceed_count: 0,
            monitor: monitor.unwrap_or_else(|| Arc::new(DummyMonitor)),
        }
    }

    /// Maximum hit count seen for a cluster.
    pub fn get_max_hit_count(&self) -> i32 {
        self.max_hit_count
    }

    /// Number of clusters that exceeded `hit_count_threshold`.
    pub fn get_exceed_count(&self) -> i32 {
        self.exceed_count
    }

    /// True if similarity and significance thresholds have been set.
    pub fn is_configured(&self) -> bool {
        self.scorer.sim_threshold > 0.0
    }

    /// The [`ExecutableScorer`] to allow examination of scores.
    pub fn get_scorer(&self) -> &ExecutableScorer {
        &self.scorer
    }

    /// Register an executable to be scored.
    ///
    /// # Errors
    ///
    /// Returns `LshException` if the executable is not in the database.
    pub fn add_executable(&mut self, md5: &str) -> Result<(), LshException> {
        let exe_record = self.lookup_executable(md5)?;
        self.scorer.add_executable(&exe_record)
    }

    /// Add all executables currently in the database to this object for comparison.
    ///
    /// # Arguments
    ///
    /// * `limit` - the max number of executables to compare against (if greater than zero)
    ///
    /// # Errors
    ///
    /// Returns `LshException` for problems retrieving executable records from the database.
    pub fn add_all_executables(&mut self, limit: i32) -> Result<(), LshException> {
        let records =
            self.database.query_exe_info(limit).ok_or_else(|| self.last_database_error())?;
        for exe_record in records {
            self.scorer.add_executable(&exe_record)?;
        }
        Ok(())
    }

    /// Remove any old scores and set new thresholds for the scorer.
    ///
    /// # Errors
    ///
    /// Returns `LshException` if there are problems saving new thresholds.
    pub fn reset_thresholds(
        &mut self,
        sim_threshold: f64,
        sig_threshold: f64,
    ) -> Result<(), LshException> {
        self.scorer.reset_storage(sim_threshold, sig_threshold)
    }

    /// Perform scoring between all registered executables.
    ///
    /// # Errors
    ///
    /// Returns [`ComparisonError::Lsh`] for any connection issues during the process, and
    /// [`ComparisonError::Cancelled`] if the monitor reports cancellation.
    pub fn perform_scoring(&mut self) -> Result<(), ComparisonError> {
        self.max_hit_count = 0;
        self.exceed_count = 0;
        self.scorer.populate_executable_index();
        if let Some(md5) = self.single_md5.clone() {
            self.scorer.set_single_executable(&md5)?;
        }
        self.pull_vectors_for_scoring_set()?;
        self.scorer.initialize_scores();

        self.monitor.set_message("Processing similar functions");
        let max_size = self.base_ids.len();
        self.monitor.initialize(max_size as i64);
        let sim_threshold = self.scorer.sim_threshold;
        let sig_threshold = self.scorer.sig_threshold;
        if sim_threshold < 0.0 {
            return Err(LshException::new("No thresholds have been established").into());
        }
        while !self.base_ids.is_empty() {
            let mut vectors: Vec<VectorResult> = Vec::new();
            let hitcount = self.build_cluster(&mut vectors, sim_threshold, sig_threshold)?;
            if hitcount == 0 {
                // Zero is possible, if all vectors in the cluster are below the sig threshold.
                continue;
            }
            else if hitcount > self.max_hit_count {
                // Keep track of the biggest hitcount.
                self.max_hit_count = hitcount;
            }
            if !self.scorer.check_preliminary_pair_threshold(hitcount, self.hit_count_threshold) {
                // Cluster is too big: count the occurrence, and don't score with this cluster.
                self.exceed_count += 1;
                continue;
            }
            let vec2_functions = self.vector_to_functions(&vectors)?;
            if !self.scorer.score_cluster(
                &self.vector_factory,
                &vec2_functions,
                &vectors,
                hitcount,
                self.hit_count_threshold,
            ) {
                self.exceed_count += 1;
                continue;
            }
            self.monitor.check_cancelled()?;
            self.monitor.set_progress((max_size - self.base_ids.len()) as i64);
        }
        // Release storage.
        self.base_ids.clear();
        self.queried_ids.clear();
        Ok(())
    }

    /// Generate any missing self-scores within the list of registered executables.
    ///
    /// # Errors
    ///
    /// Returns [`ComparisonError::Lsh`] for problems retrieving vectors, and
    /// [`ComparisonError::Cancelled`] if the user clicks "cancel".
    pub fn fillin_self_scores(&mut self) -> Result<(), ComparisonError> {
        if !self.scorer.is_single() {
            return Ok(());
        }
        let mut missing: Vec<Arc<ExecutableRecord>> = Vec::new();
        self.scorer.prefetch_self_scores(&mut missing)?;
        let size = missing.len();
        if size == 0 {
            return Ok(());
        }
        if size == 1 && Some(missing[0].get_md5()) == self.single_md5.as_deref() {
            return Ok(());
        }

        let sig_threshold = self.scorer.get_sig_threshold();
        self.monitor.set_message("Generating self-significance scores");
        self.monitor.initialize(size as i64);
        for exe_record in missing {
            let md5 = exe_record.get_md5().to_string();
            if Some(md5.as_str()) == self.single_md5.as_deref() {
                // Don't need to prefetch the singular executable.
                continue;
            }
            let mut histogram: BTreeMap<i64, Count> = BTreeMap::new();
            self.pull_vectors_for_exe(&md5, Some(&mut histogram))?;
            let mut score = 0.0;
            for (id, count) in &histogram {
                let vec_result = self.build_seed_vector(*id)?;
                let significance = self.vector_factory.get_self_significance(&vec_result.vec);
                if significance < sig_threshold {
                    continue;
                }
                score += significance * count.value as f64;
            }
            self.scorer.commit_self_score(&md5, score as f32)?;
            self.monitor.check_cancelled()?;
            self.monitor.increment_progress(1);
        }
        Ok(())
    }

    /// Look up a full [`ExecutableRecord`] in the database given an md5.
    ///
    /// # Errors
    ///
    /// Returns `LshException` if there are problems accessing the database or the executable
    /// doesn't exist.
    fn lookup_executable(&self, md5: &str) -> Result<Arc<ExecutableRecord>, LshException> {
        let manage =
            self.database.query_name(md5, 1).ok_or_else(|| self.last_database_error())?;
        if manage.num_executables() != 1 {
            return Err(LshException::new("Could not find executable"));
        }
        let first = manage.get_executable_record_set().next().map(Arc::clone);
        first.ok_or_else(|| LshException::new("Could not find executable"))
    }

    /// Query for all the vector ids associated with a specific executable, storing them in
    /// `base_ids`, or -- if `histogram` is given -- counting them there instead.
    fn pull_vectors_for_exe(
        &mut self,
        md5: &str,
        histogram: Option<&mut BTreeMap<i64, Count>>,
    ) -> Result<(), LshException> {
        let manage = self
            .database
            .query_name(md5, MAX_FUNCTIONS_PER_EXE)
            .ok_or_else(|| self.last_database_error())?;
        match histogram {
            None => {
                for function in manage.list_all_functions() {
                    self.base_ids.insert(function.get_vector_id());
                }
            }
            Some(histogram) => {
                for function in manage.list_all_functions() {
                    histogram.entry(function.get_vector_id()).or_default().value += 1;
                }
            }
        }
        Ok(())
    }

    /// Given a set of executables established for scoring, load all of the associated vector ids
    /// into `base_ids`.
    fn pull_vectors_for_scoring_set(&mut self) -> Result<(), ComparisonError> {
        self.base_ids.clear();
        self.queried_ids.clear();
        if self.scorer.is_single() {
            // If we are doing the single exe version, only pull vectors for the one executable.
            let md5 = self.single_md5.clone().unwrap_or_default();
            self.pull_vectors_for_exe(&md5, None)?;
            return Ok(());
        }
        self.monitor.set_message("Accumulating vector ids");
        let md5s: Vec<String> = self
            .scorer
            .executable_set
            .get_executable_record_set()
            .map(|record| record.get_md5().to_string())
            .collect();
        self.monitor.initialize(md5s.len() as i64);
        for md5 in md5s {
            self.pull_vectors_for_exe(&md5, None)?;
            self.monitor.check_cancelled()?;
            self.monitor.increment_progress(1);
        }
        Ok(())
    }

    /// Look up a single vector by id.
    ///
    /// # Errors
    ///
    /// Returns `LshException` if the vector does not exist.
    fn build_seed_vector(&self, id: i64) -> Result<VectorResult, LshException> {
        let mut results = self
            .database
            .query_vector_id(&[id])
            .filter(|results| results.len() == 1)
            .ok_or_else(|| LshException::new("Could not locate vector by id"))?;
        Ok(results.remove(0))
    }

    /// Pull one id out of `work_list`, look up its corresponding vector, and query for nearby
    /// vectors. Ids of the close vectors that have not been seen before are added to `work_list`;
    /// `base_ids` and `queried_ids` keep track of what has been seen and queried before.
    ///
    /// Java builds a `QueryNearestVector` around a temporary function holding the vector; the
    /// database seam takes the vector and threshold directly, since the ported signature record
    /// carries no vector yet.
    ///
    /// # Errors
    ///
    /// Returns `LshException` if something goes wrong during a query.
    fn query_vector_for_cluster(
        &mut self,
        work_list: &mut BTreeMap<i64, Option<VectorResult>>,
        threshold: f64,
    ) -> Result<VectorResult, LshException> {
        let (id, entry) = work_list
            .pop_first()
            .ok_or_else(|| LshException::new("Could not perform query on vector"))?;
        // Look up the vector and remove it from the to-do list, and mark it as queried.
        self.base_ids.remove(&id);
        self.queried_ids.insert(id);
        let current_vector = match entry {
            Some(vector) => vector,
            // If the VectorResult isn't present, this must be a seed for the cluster.
            None => self.build_seed_vector(id)?,
        };
        let response = self
            .database
            .query_nearest_vector(&current_vector.vec, threshold)
            .filter(|response| response.len() == 1)
            .ok_or_else(|| LshException::new("Could not perform query on vector"))?;
        for vec_result in response.into_iter().next().unwrap_or_default() {
            if self.queried_ids.contains(&vec_result.vectorid) {
                continue; // Already queried
            }
            work_list.insert(vec_result.vectorid, Some(vec_result));
        }
        Ok(current_vector)
    }

    /// Starting with the first vector in `base_ids`, build the cluster of vectors that are within
    /// `sim_threshold` of each other. The cluster is the "connected" component containing the
    /// first vector, where two vectors are "connected" if they are similar to each other within
    /// the threshold.
    ///
    /// Returns the total number of functions associated with any vector in the cluster.
    ///
    /// # Errors
    ///
    /// Returns `LshException` if something goes wrong during database queries.
    fn build_cluster(
        &mut self,
        cluster: &mut Vec<VectorResult>,
        sim_threshold: f64,
        sig_threshold: f64,
    ) -> Result<i32, LshException> {
        let mut work_list: BTreeMap<i64, Option<VectorResult>> = BTreeMap::new();
        let Some(first_key) = self.base_ids.pop_first() else {
            return Ok(0);
        };
        work_list.insert(first_key, None);
        let mut hit_count = 0;
        while !work_list.is_empty() {
            // Retrieve the vector, and add the vectors close to it.
            let vector_info = self.query_vector_for_cluster(&mut work_list, sim_threshold)?;
            if sig_threshold < self.vector_factory.get_self_significance(&vector_info.vec) {
                // If the self-significance exceeds the threshold, add it to the cluster.
                hit_count += vector_info.hitcount;
                cluster.push(vector_info);
            }
        }
        Ok(hit_count)
    }

    /// For each vector in `cluster`, query the database and populate a container with the
    /// functions associated with the vector, returning the list of containers.
    ///
    /// # Errors
    ///
    /// Returns `LshException` if anything goes wrong with queries.
    fn vector_to_functions(
        &self,
        cluster: &[VectorResult],
    ) -> Result<Vec<DescriptionManager>, LshException> {
        let mut result = Vec::with_capacity(cluster.len());
        for vector in cluster {
            // vector.hitcount should be exact, but set the threshold slightly higher so we can
            // tell if we exceeded the hitcount.
            let manage = self
                .database
                .query_vector_match(&[vector.vectorid], vector.hitcount + 10)
                .ok_or_else(|| self.last_database_error())?;
            self.scorer.label_and_filter(&manage);
            result.push(manage);
        }
        Ok(result)
    }

    /// Java: `new LSHException(database.getLastError().message)`.
    fn last_database_error(&self) -> LshException {
        LshException::new(self.database.get_last_error().message)
    }
}

impl fmt::Debug for ExecutableComparison {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecutableComparison")
            .field("single_md5", &self.single_md5)
            .field("hit_count_threshold", &self.hit_count_threshold)
            .field("max_hit_count", &self.max_hit_count)
            .field("exceed_count", &self.exceed_count)
            .field("scorer", &self.scorer)
            .finish()
    }
}

/// Make sure the database has an active connection. Query for basic information, and hand back
/// what the scorer and the comparison need from the connection.
///
/// # Errors
///
/// Returns `LshException` if something is wrong with the connection.
fn pull_connection_info(
    database: &dyn FunctionDatabase,
) -> Result<(DatabaseInformation, Arc<LSHVectorFactory>), LshException> {
    if !database.initialize() {
        return Err(LshException::new("Unable to connect to server"));
    }
    let info = database
        .query_info()
        .ok_or_else(|| LshException::new(database.get_last_error().message))?;
    Ok((info, database.get_lsh_vector_factory()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    use crate::feature::bsim::query::function_database::{
        BSimError, ConnectionType, ErrorCategory, Status,
    };
    use crate::feature::bsim::query::BSimServerInfo;
    use crate::feature::seam_stubs::{BSimQuery, QueryResponseRecord};
    use crate::generic::seam_stubs::WeightedLSHCosineVector;

    const EXE_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const EXE_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// A vector id, and the functions (one per md5) that instantiate it.
    struct VectorFixture {
        id: i64,
        /// Feature hashes, which decide the vector's self-significance.
        features: Vec<i32>,
        exes: Vec<&'static str>,
    }

    struct MockDatabase {
        connected: bool,
        vectors: Vec<VectorFixture>,
        error: String,
        /// Records every `query_name` md5, so the tests can see which executables were pulled.
        queried_names: Mutex<Vec<String>>,
    }

    impl MockDatabase {
        fn new(vectors: Vec<VectorFixture>) -> Self {
            Self {
                connected: true,
                vectors,
                error: "database is unhappy".to_string(),
                queried_names: Mutex::new(Vec::new()),
            }
        }

        fn vector(&self, id: i64) -> Option<&VectorFixture> {
            self.vectors.iter().find(|v| v.id == id)
        }

        fn vector_result(fixture: &VectorFixture) -> VectorResult {
            VectorResult::new(
                fixture.id,
                fixture.exes.len() as i32,
                1.0,
                1.0,
                WeightedLSHCosineVector::from_features(&fixture.features),
            )
        }

        /// A container holding the executable and, optionally, its functions.
        fn build_manager(&self, md5: &str, with_functions: bool) -> DescriptionManager {
            let mut manage = DescriptionManager::new();
            let exe =
                manage.new_executable_record(md5, "exe", "gcc", "x86:LE:64:default", 0, None, None, None).unwrap();
            if with_functions {
                for (index, fixture) in
                    self.vectors.iter().filter(|v| v.exes.contains(&md5)).enumerate()
                {
                    let mut function = manage.new_function_description(
                        &format!("func_{}", index),
                        0x1000 + index as i64,
                        Arc::clone(&exe),
                    );
                    manage.set_signature_id(&mut function, fixture.id);
                    manage.insert_function(function);
                }
            }
            manage
        }
    }

    impl FunctionDatabase for MockDatabase {
        fn initialize(&self) -> bool {
            self.connected
        }

        fn get_last_error(&self) -> BSimError {
            BSimError::new(ErrorCategory::Connection, self.error.clone())
        }

        fn get_lsh_vector_factory(&self) -> Arc<LSHVectorFactory> {
            Arc::new(LSHVectorFactory::with_settings(7))
        }

        fn query_info(&self) -> Option<DatabaseInformation> {
            let mut info = DatabaseInformation::new();
            info.major = 4;
            info.minor = 2;
            info.settings = 7;
            Some(info)
        }

        fn query_name(&self, md5: &str, max_func: i32) -> Option<DescriptionManager> {
            self.queried_names.lock().unwrap().push(md5.to_string());
            if md5 != EXE_A && md5 != EXE_B {
                return Some(DescriptionManager::new());
            }
            Some(self.build_manager(md5, max_func > 1))
        }

        fn query_exe_info(&self, limit: i32) -> Option<Vec<Arc<ExecutableRecord>>> {
            let mut records = Vec::new();
            for md5 in [EXE_A, EXE_B] {
                if limit > 0 && records.len() as i32 >= limit {
                    break;
                }
                let manage = self.build_manager(md5, false);
                records.push(Arc::clone(manage.get_executable_record_set().next().unwrap()));
            }
            Some(records)
        }

        fn query_vector_id(&self, ids: &[i64]) -> Option<Vec<VectorResult>> {
            ids.iter().map(|id| self.vector(*id).map(Self::vector_result)).collect()
        }

        fn query_nearest_vector(
            &self,
            vec: &WeightedLSHCosineVector,
            _thresh: f64,
        ) -> Option<Vec<Vec<VectorResult>>> {
            // Every vector with the same number of features is "near" the queried one.
            use crate::generic::lsh::vector::lsh_vector::LSHVector;
            let near: Vec<VectorResult> = self
                .vectors
                .iter()
                .filter(|fixture| fixture.features.len() as i32 == vec.num_entries())
                .map(Self::vector_result)
                .collect();
            Some(vec![near])
        }

        fn query_vector_match(
            &self,
            vector_ids: &[i64],
            _max: i32,
        ) -> Option<DescriptionManager> {
            let mut manage = DescriptionManager::new();
            for id in vector_ids {
                let fixture = self.vector(*id)?;
                for md5 in &fixture.exes {
                    let exe = manage
                        .new_executable_record(md5, "exe", "gcc", "x86:LE:64:default", 0, None, None, None)
                        .unwrap();
                    let mut function =
                        manage.new_function_description("func", 0x1000, Arc::clone(&exe));
                    manage.set_signature_id(&mut function, *id);
                    manage.insert_function(function);
                }
            }
            Some(manage)
        }

        fn get_status(&self) -> Status {
            unimplemented!("not used by ExecutableComparison")
        }

        fn get_connection_type(&self) -> ConnectionType {
            unimplemented!("not used by ExecutableComparison")
        }

        fn get_user_name(&self) -> String {
            unimplemented!("not used by ExecutableComparison")
        }

        fn get_info(&self) -> Option<DatabaseInformation> {
            unimplemented!("not used by ExecutableComparison")
        }

        fn compare_layout(&self) -> i32 {
            unimplemented!("not used by ExecutableComparison")
        }

        fn get_server_info(&self) -> BSimServerInfo {
            unimplemented!("not used by ExecutableComparison")
        }

        fn get_url_string(&self) -> String {
            unimplemented!("not used by ExecutableComparison")
        }

        fn close(&self) {}

        fn query(&self, _query: &dyn BSimQuery) -> Option<Box<dyn QueryResponseRecord>> {
            unimplemented!("not used by ExecutableComparison")
        }
    }

    /// Two vectors shared by both executables, plus one only executable A has.
    fn standard_fixtures() -> Vec<VectorFixture> {
        vec![
            VectorFixture { id: 10, features: vec![1, 2, 3], exes: vec![EXE_A, EXE_B] },
            VectorFixture { id: 20, features: vec![4, 5, 6], exes: vec![EXE_A, EXE_B] },
            VectorFixture { id: 30, features: vec![7, 8], exes: vec![EXE_A] },
        ]
    }

    fn database() -> Arc<MockDatabase> {
        Arc::new(MockDatabase::new(standard_fixtures()))
    }

    #[test]
    fn matrix_constructor_transfers_database_settings_to_the_scorer() {
        let comparison = ExecutableComparison::new(database(), 100, None).unwrap();
        // Java: scorer.transferSettings(info) copies version and settings onto executableSet.
        let executable_set = &comparison.get_scorer().executable_set;
        assert_eq!(executable_set.get_major_version(), 4);
        assert_eq!(executable_set.get_minor_version(), 2);
        assert_eq!(executable_set.get_settings(), 7);
        // Java: a fresh matrix scorer has no thresholds, so it is not configured.
        assert!(!comparison.is_configured());
        assert!(!comparison.get_scorer().is_single());
    }

    #[test]
    fn constructor_fails_when_the_connection_is_not_established() {
        let mut db = MockDatabase::new(standard_fixtures());
        db.connected = false;
        let error = ExecutableComparison::new(Arc::new(db), 100, None).unwrap_err();
        assert_eq!(error.message(), "Unable to connect to server");
    }

    #[test]
    fn single_constructor_registers_the_singled_out_executable() {
        let comparison =
            ExecutableComparison::new_single(database(), 100, EXE_A, None, None).unwrap();
        assert!(comparison.get_scorer().is_single());
        assert_eq!(comparison.get_scorer().num_executables(), 1);
        assert!(comparison.get_scorer().executable_set.find_executable(EXE_A).is_ok());
    }

    #[test]
    fn add_executable_rejects_an_md5_that_is_not_in_the_database() {
        let mut comparison = ExecutableComparison::new(database(), 100, None).unwrap();
        let error = comparison.add_executable("cccccccccccccccccccccccccccccccc").unwrap_err();
        assert_eq!(error.message(), "Could not find executable");
        assert_eq!(comparison.get_scorer().num_executables(), 0);
    }

    #[test]
    fn add_all_executables_honors_the_limit() {
        let mut comparison = ExecutableComparison::new(database(), 100, None).unwrap();
        comparison.add_all_executables(1).unwrap();
        assert_eq!(comparison.get_scorer().num_executables(), 1);
        comparison.add_all_executables(0).unwrap();
        assert_eq!(comparison.get_scorer().num_executables(), 2);
    }

    #[test]
    fn reset_thresholds_configures_the_scorer() {
        let mut comparison = ExecutableComparison::new(database(), 100, None).unwrap();
        assert!(!comparison.is_configured());
        comparison.reset_thresholds(0.7, 0.5).unwrap();
        assert!(comparison.is_configured());
        assert_eq!(comparison.get_scorer().get_sim_threshold(), 0.7);
        assert_eq!(comparison.get_scorer().get_sig_threshold(), 0.5);
    }

    #[test]
    fn perform_scoring_fails_without_thresholds() {
        let mut comparison = ExecutableComparison::new(database(), 100, None).unwrap();
        comparison.add_all_executables(0).unwrap();
        match comparison.perform_scoring().unwrap_err() {
            ComparisonError::Lsh(e) => {
                assert_eq!(e.message(), "No thresholds have been established")
            }
            other => panic!("expected an LSHException, got {:?}", other),
        }
    }

    #[test]
    fn perform_scoring_clusters_every_vector_of_the_registered_executables() {
        let mut comparison = ExecutableComparison::new(database(), 1000, None).unwrap();
        comparison.add_all_executables(0).unwrap();
        comparison.reset_thresholds(0.7, 0.5).unwrap();
        comparison.perform_scoring().unwrap();

        // Vectors 10 and 20 have three features each, so they cluster together and their
        // hitcounts (2 executables apiece) add up; vector 30 clusters alone with hitcount 1.
        assert_eq!(comparison.get_max_hit_count(), 4);
        assert_eq!(comparison.get_exceed_count(), 0);
        // Both clusters were scored, and the executables kept their xref indices.
        assert_eq!(comparison.get_scorer().clusters_scored(), 2);
        assert_eq!(comparison.get_scorer().num_executables(), 2);
    }

    #[test]
    fn perform_scoring_counts_clusters_that_exceed_the_hit_count_threshold() {
        // A threshold of 2 admits the singleton cluster (1 pair) but not the 4-hit cluster,
        // which Java's checkPreliminaryPairThreshold values at 4*5/2 = 10 pairs.
        let mut comparison = ExecutableComparison::new(database(), 2, None).unwrap();
        comparison.add_all_executables(0).unwrap();
        comparison.reset_thresholds(0.7, 0.5).unwrap();
        comparison.perform_scoring().unwrap();

        assert_eq!(comparison.get_max_hit_count(), 4);
        assert_eq!(comparison.get_exceed_count(), 1);
        assert_eq!(comparison.get_scorer().clusters_scored(), 1);
    }

    #[test]
    fn perform_scoring_drops_clusters_below_the_significance_threshold() {
        let mut comparison = ExecutableComparison::new(database(), 1000, None).unwrap();
        comparison.add_all_executables(0).unwrap();
        // Self-significance of the placeholder factory is the squared vector length: 3.0 for the
        // three-feature vectors and 2.0 for the two-feature one, so only the former survive.
        comparison.reset_thresholds(0.7, 2.5).unwrap();
        comparison.perform_scoring().unwrap();

        assert_eq!(comparison.get_max_hit_count(), 4);
        assert_eq!(comparison.get_exceed_count(), 0);
        // The two-feature vector formed a cluster with a zero hitcount, which contributes nothing.
        assert_eq!(comparison.get_scorer().clusters_scored(), 1);
    }

    #[test]
    fn fillin_self_scores_is_a_no_op_for_the_matrix_scorer() {
        let mut comparison = ExecutableComparison::new(database(), 100, None).unwrap();
        comparison.add_all_executables(0).unwrap();
        comparison.fillin_self_scores().unwrap();
    }

    /// A cache that starts out knowing no scores, so every registered executable comes back as
    /// missing. The score map is shared so a test can see what was committed.
    struct EmptyCache {
        scores: Arc<Mutex<HashMap<String, f32>>>,
        sim_threshold: f64,
        sig_threshold: f64,
    }

    impl EmptyCache {
        fn new(sim_threshold: f64, sig_threshold: f64) -> (Box<Self>, Arc<Mutex<HashMap<String, f32>>>) {
            let scores = Arc::new(Mutex::new(HashMap::new()));
            let cache =
                Box::new(Self { scores: Arc::clone(&scores), sim_threshold, sig_threshold });
            (cache, scores)
        }
    }

    impl ScoreCaching for EmptyCache {
        fn prefetch_scores(
            &mut self,
            _exe_set: std::collections::HashSet<ExecutableRecord>,
            _missing: Option<&mut Vec<ExecutableRecord>>,
        ) -> Result<(), LshException> {
            Ok(())
        }

        fn get_self_score(&self, md5: &str) -> Result<f32, LshException> {
            self.scores
                .lock()
                .unwrap()
                .get(md5)
                .copied()
                .ok_or_else(|| LshException::new("No score"))
        }

        fn commit_self_score(&mut self, md5: &str, score: f32) -> Result<(), LshException> {
            self.scores.lock().unwrap().insert(md5.to_string(), score);
            Ok(())
        }

        fn get_sim_threshold(&self) -> Result<f64, LshException> {
            Ok(self.sim_threshold)
        }

        fn get_sig_threshold(&self) -> Result<f64, LshException> {
            Ok(self.sig_threshold)
        }

        fn reset_storage(&mut self, sim_thresh: f64, sig_thresh: f64) -> Result<(), LshException> {
            self.scores.lock().unwrap().clear();
            self.sim_threshold = sim_thresh;
            self.sig_threshold = sig_thresh;
            Ok(())
        }
    }

    #[test]
    fn single_scorer_takes_its_thresholds_from_the_cache() {
        let (cache, _scores) = EmptyCache::new(0.75, 1.0);
        let comparison =
            ExecutableComparison::new_single(database(), 100, EXE_A, Some(cache), None).unwrap();
        assert!(comparison.is_configured());
        assert_eq!(comparison.get_scorer().get_sim_threshold(), 0.75);
        assert_eq!(comparison.get_scorer().get_sig_threshold(), 1.0);
    }

    #[test]
    fn fillin_self_scores_commits_a_score_for_every_uncached_executable() {
        let (cache, scores) = EmptyCache::new(0.75, 1.0);
        let mut comparison =
            ExecutableComparison::new_single(database(), 100, EXE_A, Some(cache), None).unwrap();
        comparison.add_executable(EXE_B).unwrap();
        comparison.fillin_self_scores().unwrap();

        // Executable B instantiates vectors 10 and 20 once each, both with self-significance 3.0
        // (the squared length of a three-feature placeholder vector), so its self-score is their
        // sum. The singled out executable A is skipped, as Java does.
        let scores = scores.lock().unwrap();
        assert_eq!(scores.get(EXE_B).copied(), Some(6.0));
        assert_eq!(scores.get(EXE_A), None);
    }

    #[test]
    fn fillin_self_scores_skips_an_executable_below_the_significance_threshold() {
        // With the threshold above every vector's self-significance, nothing contributes.
        let (cache, scores) = EmptyCache::new(0.75, 10.0);
        let mut comparison =
            ExecutableComparison::new_single(database(), 100, EXE_A, Some(cache), None).unwrap();
        comparison.add_executable(EXE_B).unwrap();
        comparison.fillin_self_scores().unwrap();

        assert_eq!(scores.lock().unwrap().get(EXE_B).copied(), Some(0.0));
    }

    #[test]
    fn single_scorer_only_pulls_vectors_for_the_singled_out_executable() {
        let (cache, _scores) = EmptyCache::new(0.75, 0.5);
        let db = database();
        let connection: Arc<dyn FunctionDatabase> = Arc::clone(&db) as Arc<dyn FunctionDatabase>;
        let mut comparison =
            ExecutableComparison::new_single(connection, 1000, EXE_A, Some(cache), None).unwrap();
        comparison.add_executable(EXE_B).unwrap();
        db.queried_names.lock().unwrap().clear();
        comparison.perform_scoring().unwrap();

        // Java's pullVectorsForScoringSet queries only singleMd5 when the scorer is the row
        // scorer, no matter how many executables are registered.
        let names = db.queried_names.lock().unwrap();
        assert!(names.iter().all(|md5| md5 == EXE_A), "queried {:?}", names);
        assert!(names.contains(&EXE_A.to_string()));
    }
}
