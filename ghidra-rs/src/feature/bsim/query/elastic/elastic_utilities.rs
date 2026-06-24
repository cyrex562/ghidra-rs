/// Tokenizer settings key names for the BSim Elastic backend.
///
/// Mirrors `ghidra.features.bsim.query.elastic.ElasticUtilities`.
pub const K_SETTING: &str = "k_setting";
pub const L_SETTING: &str = "l_setting";
pub const LSH_WEIGHTS: &str = "lsh_weights";
pub const IDF_CONFIG: &str = "idf_config";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_k_setting() {
        assert_eq!(K_SETTING, "k_setting");
    }

    #[test]
    fn test_l_setting() {
        assert_eq!(L_SETTING, "l_setting");
    }

    #[test]
    fn test_lsh_weights() {
        assert_eq!(LSH_WEIGHTS, "lsh_weights");
    }

    #[test]
    fn test_idf_config() {
        assert_eq!(IDF_CONFIG, "idf_config");
    }

    #[test]
    fn test_constants_are_distinct() {
        let all = [K_SETTING, L_SETTING, LSH_WEIGHTS, IDF_CONFIG];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j]);
            }
        }
    }
}
