/// Named graph layout algorithms available in the Ghidra graph framework.
pub const FORCED_BALANCED: &str = "Force Balanced";
pub const FORCE_DIRECTED: &str = "Force Directed";
pub const CIRCLE: &str = "Circle";
pub const COMPACT_HIERARCHICAL: &str = "Compact Hierarchical";
pub const COMPACT_RADIAL: &str = "Compact Radial";
pub const MIN_CROSS_TOP_DOWN: &str = "Hierarchical MinCross Top Down";
pub const MIN_CROSS_LONGEST_PATH: &str = "Hierarchical MinCross Longest Path";
pub const MIN_CROSS_NETWORK_SIMPLEX: &str = "Hierarchical MinCross Network Simplex";
pub const MIN_CROSS_COFFMAN_GRAHAM: &str = "Hierarchical MinCross Coffman Graham";
pub const VERT_MIN_CROSS_TOP_DOWN: &str = "Vertical Hierarchical MinCross Top Down";
pub const VERT_MIN_CROSS_LONGEST_PATH: &str = "Vertical Hierarchical MinCross Longest Path";
pub const VERT_MIN_CROSS_NETWORK_SIMPLEX: &str = "Vertical Hierarchical MinCross Network Simplex";
pub const VERT_MIN_CROSS_COFFMAN_GRAHAM: &str = "Vertical Hierarchical MinCross Coffman Graham";
pub const HIERACHICAL: &str = "Hierarchical";
pub const RADIAL: &str = "Radial";
pub const BALLOON: &str = "Balloon";
pub const GEM: &str = "GEM";

/// Returns the full ordered list of layout algorithm names, matching Java's
/// `LayoutAlgorithmNames.getLayoutAlgorithmNames()`.
pub fn get_layout_algorithm_names() -> Vec<&'static str> {
    vec![
        COMPACT_HIERARCHICAL,
        HIERACHICAL,
        COMPACT_RADIAL,
        MIN_CROSS_TOP_DOWN,
        MIN_CROSS_LONGEST_PATH,
        MIN_CROSS_NETWORK_SIMPLEX,
        MIN_CROSS_COFFMAN_GRAHAM,
        CIRCLE,
        VERT_MIN_CROSS_TOP_DOWN,
        VERT_MIN_CROSS_LONGEST_PATH,
        VERT_MIN_CROSS_NETWORK_SIMPLEX,
        VERT_MIN_CROSS_COFFMAN_GRAHAM,
        FORCED_BALANCED,
        FORCE_DIRECTED,
        RADIAL,
        BALLOON,
        GEM,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_names_returned_in_java_order() {
        let names = get_layout_algorithm_names();
        assert_eq!(names.len(), 17);
        assert_eq!(names[0], COMPACT_HIERARCHICAL);
        assert_eq!(names[1], HIERACHICAL);
        assert_eq!(names[2], COMPACT_RADIAL);
        assert_eq!(names[3], MIN_CROSS_TOP_DOWN);
        assert_eq!(names[4], MIN_CROSS_LONGEST_PATH);
        assert_eq!(names[5], MIN_CROSS_NETWORK_SIMPLEX);
        assert_eq!(names[6], MIN_CROSS_COFFMAN_GRAHAM);
        assert_eq!(names[7], CIRCLE);
        assert_eq!(names[8], VERT_MIN_CROSS_TOP_DOWN);
        assert_eq!(names[9], VERT_MIN_CROSS_LONGEST_PATH);
        assert_eq!(names[10], VERT_MIN_CROSS_NETWORK_SIMPLEX);
        assert_eq!(names[11], VERT_MIN_CROSS_COFFMAN_GRAHAM);
        assert_eq!(names[12], FORCED_BALANCED);
        assert_eq!(names[13], FORCE_DIRECTED);
        assert_eq!(names[14], RADIAL);
        assert_eq!(names[15], BALLOON);
        assert_eq!(names[16], GEM);
    }

    #[test]
    fn constants_have_correct_string_values() {
        assert_eq!(FORCED_BALANCED, "Force Balanced");
        assert_eq!(FORCE_DIRECTED, "Force Directed");
        assert_eq!(CIRCLE, "Circle");
        assert_eq!(COMPACT_HIERARCHICAL, "Compact Hierarchical");
        assert_eq!(COMPACT_RADIAL, "Compact Radial");
        assert_eq!(MIN_CROSS_TOP_DOWN, "Hierarchical MinCross Top Down");
        assert_eq!(MIN_CROSS_LONGEST_PATH, "Hierarchical MinCross Longest Path");
        assert_eq!(MIN_CROSS_NETWORK_SIMPLEX, "Hierarchical MinCross Network Simplex");
        assert_eq!(MIN_CROSS_COFFMAN_GRAHAM, "Hierarchical MinCross Coffman Graham");
        assert_eq!(VERT_MIN_CROSS_TOP_DOWN, "Vertical Hierarchical MinCross Top Down");
        assert_eq!(VERT_MIN_CROSS_LONGEST_PATH, "Vertical Hierarchical MinCross Longest Path");
        assert_eq!(VERT_MIN_CROSS_NETWORK_SIMPLEX, "Vertical Hierarchical MinCross Network Simplex");
        assert_eq!(VERT_MIN_CROSS_COFFMAN_GRAHAM, "Vertical Hierarchical MinCross Coffman Graham");
        assert_eq!(HIERACHICAL, "Hierarchical");
        assert_eq!(RADIAL, "Radial");
        assert_eq!(BALLOON, "Balloon");
        assert_eq!(GEM, "GEM");
    }

    #[test]
    fn no_duplicate_names_in_list() {
        let names = get_layout_algorithm_names();
        let mut seen = std::collections::HashSet::new();
        for name in &names {
            assert!(seen.insert(*name), "duplicate entry: {name}");
        }
    }
}
