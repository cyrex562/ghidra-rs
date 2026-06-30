/// Controls when graph layout is automatically re-applied after a change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelayoutOption {
    Always,
    BlockModelChanges,
    VertexGroupingChanges,
    Never,
}

impl RelayoutOption {
    pub fn display_name(self) -> &'static str {
        match self {
            Self::Always => "Always",
            Self::BlockModelChanges => "Block Model Changes Only",
            Self::VertexGroupingChanges => "Vertex Grouping Changes Only",
            Self::Never => "Never",
        }
    }
}

impl std::fmt::Display for RelayoutOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.display_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_always() {
        assert_eq!(RelayoutOption::Always.to_string(), "Always");
    }

    #[test]
    fn test_display_block_model_changes() {
        assert_eq!(
            RelayoutOption::BlockModelChanges.to_string(),
            "Block Model Changes Only"
        );
    }

    #[test]
    fn test_display_vertex_grouping_changes() {
        assert_eq!(
            RelayoutOption::VertexGroupingChanges.to_string(),
            "Vertex Grouping Changes Only"
        );
    }

    #[test]
    fn test_display_never() {
        assert_eq!(RelayoutOption::Never.to_string(), "Never");
    }

    #[test]
    fn test_copy() {
        let a = RelayoutOption::Always;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn test_equality() {
        assert_eq!(RelayoutOption::Never, RelayoutOption::Never);
        assert_ne!(RelayoutOption::Always, RelayoutOption::Never);
    }

    #[test]
    fn test_debug() {
        assert_eq!(format!("{:?}", RelayoutOption::Always), "Always");
        assert_eq!(format!("{:?}", RelayoutOption::Never), "Never");
    }

    #[test]
    fn test_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(RelayoutOption::Always);
        set.insert(RelayoutOption::Never);
        assert_eq!(set.len(), 2);
        set.insert(RelayoutOption::Always);
        assert_eq!(set.len(), 2);
    }
}
