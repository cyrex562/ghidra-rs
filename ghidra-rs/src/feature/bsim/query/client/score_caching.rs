use std::collections::HashSet;

use crate::feature::bsim::query::LshException;
use crate::feature::seam_stubs::ExecutableRecord;

/// Store and retrieve self-significance scores for executables specified by md5.
///
/// These are generally too expensive to compute on the fly, so this trait
/// provides a persistence model for obtaining them. These scores also depend
/// on specific threshold settings, so there is a method for checking the settings.
///
/// Mirrors `ghidra.features.bsim.query.client.ScoreCaching`.
pub trait ScoreCaching: Send + Sync {
    /// Pre-load self-scores for a set of executables.
    ///
    /// # Arguments
    ///
    /// * `exe_set` - the set of executables to check
    /// * `missing` - optional container that will be filled with the list of exes missing a score
    ///
    /// # Errors
    ///
    /// Returns `LshException` if there are problems loading scores.
    fn prefetch_scores(
        &mut self,
        exe_set: HashSet<ExecutableRecord>,
        missing: Option<&mut Vec<ExecutableRecord>>,
    ) -> Result<(), LshException>;

    /// Retrieve the self-significance score for a given executable.
    ///
    /// # Arguments
    ///
    /// * `md5` - the 32-character md5 string specifying the executable
    ///
    /// # Returns
    ///
    /// The corresponding score.
    ///
    /// # Errors
    ///
    /// Returns `LshException` if the score is not obtainable.
    fn get_self_score(&self, md5: &str) -> Result<f32, LshException>;

    /// Commit a new self-significance score for an executable.
    ///
    /// # Arguments
    ///
    /// * `md5` - the 32-character md5 string specifying the executable
    /// * `score` - the score to commit
    ///
    /// # Errors
    ///
    /// Returns `LshException` if there's a problem saving the value.
    fn commit_self_score(&mut self, md5: &str, score: f32) -> Result<(), LshException>;

    /// Get the similarity threshold configured with this cache.
    ///
    /// # Returns
    ///
    /// The similarity threshold, or -1.0 if the score is unconfigured.
    ///
    /// # Errors
    ///
    /// Returns `LshException` for problems retrieving configuration.
    fn get_sim_threshold(&self) -> Result<f64, LshException>;

    /// Get the significance threshold configured with this cache.
    ///
    /// # Returns
    ///
    /// The significance threshold, or -1.0 if the score is unconfigured.
    ///
    /// # Errors
    ///
    /// Returns `LshException` for problems retrieving configuration.
    fn get_sig_threshold(&self) -> Result<f64, LshException>;

    /// Clear out any existing scores, and reset to an empty database.
    ///
    /// # Arguments
    ///
    /// * `sim_thresh` - new similarity threshold to associate with scores
    /// * `sig_thresh` - new significance threshold to associate with scores
    ///
    /// # Errors
    ///
    /// Returns `LshException` if there is a problem modifying storage.
    fn reset_storage(&mut self, sim_thresh: f64, sig_thresh: f64) -> Result<(), LshException>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mock implementation of ScoreCaching for testing.
    struct MockScoreCaching {
        scores: std::collections::HashMap<String, f32>,
        sim_threshold: f64,
        sig_threshold: f64,
    }

    impl MockScoreCaching {
        fn new() -> Self {
            Self {
                scores: std::collections::HashMap::new(),
                sim_threshold: -1.0,
                sig_threshold: -1.0,
            }
        }
    }

    impl ScoreCaching for MockScoreCaching {
        fn prefetch_scores(
            &mut self,
            exe_set: HashSet<ExecutableRecord>,
            missing: Option<&mut Vec<ExecutableRecord>>,
        ) -> Result<(), LshException> {
            let mut missing_list = Vec::new();
            for exe in exe_set {
                if !self.scores.contains_key(exe.get_md5()) {
                    missing_list.push(exe);
                }
            }
            if let Some(missing_vec) = missing {
                *missing_vec = missing_list;
            }
            Ok(())
        }

        fn get_self_score(&self, md5: &str) -> Result<f32, LshException> {
            self.scores
                .get(md5)
                .copied()
                .ok_or_else(|| LshException::new(format!("Score not found for md5: {}", md5)))
        }

        fn commit_self_score(&mut self, md5: &str, score: f32) -> Result<(), LshException> {
            if !(0.0..=1.0).contains(&score) {
                return Err(LshException::new(format!("Invalid score: {}", score)));
            }
            self.scores.insert(md5.to_string(), score);
            Ok(())
        }

        fn get_sim_threshold(&self) -> Result<f64, LshException> {
            Ok(self.sim_threshold)
        }

        fn get_sig_threshold(&self) -> Result<f64, LshException> {
            Ok(self.sig_threshold)
        }

        fn reset_storage(&mut self, sim_thresh: f64, sig_thresh: f64) -> Result<(), LshException> {
            self.scores.clear();
            self.sim_threshold = sim_thresh;
            self.sig_threshold = sig_thresh;
            Ok(())
        }
    }

    #[test]
    fn test_commit_and_retrieve_score() {
        let mut cache = MockScoreCaching::new();
        let md5 = "abc123def456";
        let score = 0.75;

        cache.commit_self_score(md5, score).unwrap();
        assert_eq!(cache.get_self_score(md5).unwrap(), score);
    }

    #[test]
    fn test_get_nonexistent_score_fails() {
        let cache = MockScoreCaching::new();
        let result = cache.get_self_score("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_commit_invalid_score_fails() {
        let mut cache = MockScoreCaching::new();
        let result = cache.commit_self_score("md5", 1.5);
        assert!(result.is_err());
    }

    #[test]
    fn test_reset_storage_clears_scores() {
        let mut cache = MockScoreCaching::new();
        cache.commit_self_score("md5_1", 0.5).unwrap();
        cache.commit_self_score("md5_2", 0.7).unwrap();

        cache.reset_storage(0.6, 0.8).unwrap();

        assert!(cache.get_self_score("md5_1").is_err());
        assert!(cache.get_self_score("md5_2").is_err());
        assert_eq!(cache.get_sim_threshold().unwrap(), 0.6);
        assert_eq!(cache.get_sig_threshold().unwrap(), 0.8);
    }

    #[test]
    fn test_threshold_defaults_to_minus_one() {
        let cache = MockScoreCaching::new();
        assert_eq!(cache.get_sim_threshold().unwrap(), -1.0);
        assert_eq!(cache.get_sig_threshold().unwrap(), -1.0);
    }

    #[test]
    fn test_prefetch_scores_identifies_missing() {
        let mut cache = MockScoreCaching::new();
        let md5_1 = "abc123";
        let md5_2 = "def456";

        cache.commit_self_score(md5_1, 0.5).unwrap();

        let exe1 = ExecutableRecord::new(md5_1, "exe1", "x86", "gcc");
        let exe2 = ExecutableRecord::new(md5_2, "exe2", "x86", "gcc");
        let mut exe_set = HashSet::new();
        exe_set.insert(exe1);
        exe_set.insert(exe2);

        let mut missing = Vec::new();
        cache.prefetch_scores(exe_set, Some(&mut missing)).unwrap();

        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].get_md5(), md5_2);
    }

    #[test]
    fn test_prefetch_scores_with_none_missing() {
        let mut cache = MockScoreCaching::new();
        let exe = ExecutableRecord::new("abc123", "exe1", "x86", "gcc");
        let mut exe_set = HashSet::new();
        exe_set.insert(exe);

        let result = cache.prefetch_scores(exe_set, None);
        assert!(result.is_ok());
    }
}
