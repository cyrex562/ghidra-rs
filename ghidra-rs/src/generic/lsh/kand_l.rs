use std::f64::consts::PI;

use super::LshMemoryModel;

/// Given a lower bound on cosine similarity, `tau`, calculate the probability
/// that a random hyperplane projection places two vectors whose similarity
/// meets this bound into the same bin.
///
/// `Pr[ h(v) = h(w) ] = 1 - theta / pi`, where `theta` is the angle between
/// `v` and `w`.
///
/// Mirrors `generic.lsh.KandL.probOfHashMatch` from Ghidra.
fn prob_of_hash_match(tau: f64) -> f64 {
    let thetabound = tau.acos();
    1.0 - thetabound / PI
}

/// Computes the number of hash tables `L` needed for the given memory model.
///
/// Mirrors `generic.lsh.KandL.memoryModelToL` from Ghidra.
pub fn memory_model_to_l(model: LshMemoryModel) -> i32 {
    k_to_l(model.k(), model.tau_bound(), model.probability_threshold())
}

/// Given a hash size `k`, a lower bound on cosine similarity `taubound`, and
/// the desired probability `probthresh` of finding a match, calculates the
/// number of hash tables `L` required to achieve that probability.
///
/// Mirrors `generic.lsh.KandL.kToL` from Ghidra.
pub fn k_to_l(k: i32, taubound: f64, probthresh: f64) -> i32 {
    let p1 = prob_of_hash_match(taubound);
    let prob_k_matches = p1.powi(k);
    let prob_nomatch = 1.0 - prob_k_matches;
    let mut l = 1;
    let mut prob_nomatch_n = prob_nomatch;
    while 1.0 - prob_nomatch_n < probthresh {
        l += 1;
        prob_nomatch_n *= prob_nomatch;
    }
    l
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prob_of_hash_match_at_tau_one_is_one() {
        assert!((prob_of_hash_match(1.0) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn prob_of_hash_match_at_tau_zero_is_half() {
        assert!((prob_of_hash_match(0.0) - 0.5).abs() < 1e-9);
    }

    #[test]
    fn k_to_l_increases_with_higher_probability_threshold() {
        let l_low = k_to_l(13, 0.75, 0.9);
        let l_high = k_to_l(13, 0.75, 0.999);
        assert!(l_high >= l_low);
    }

    #[test]
    fn k_to_l_is_at_least_one() {
        assert!(k_to_l(10, 0.75, 0.5) >= 1);
    }

    #[test]
    fn memory_model_to_l_matches_k_to_l() {
        let model = LshMemoryModel::Medium;
        let expected =
            k_to_l(model.k(), model.tau_bound(), model.probability_threshold());
        assert_eq!(memory_model_to_l(model), expected);
    }

    #[test]
    fn memory_model_to_l_is_positive_for_all_models() {
        for model in [
            LshMemoryModel::Small,
            LshMemoryModel::Medium,
            LshMemoryModel::Large,
        ] {
            assert!(memory_model_to_l(model) >= 1);
        }
    }
}
