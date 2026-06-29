/// Controls which functions are shown in the VT function-association table.
///
/// Mirrors `VTFunctionAssociationMode` from the Java source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VtFunctionAssociationMode {
    /// Show all functions.
    All,
    /// Show only functions that are not yet matched.
    NonMatched,
    /// Show only caller functions.
    Caller,
    /// Show only callee functions.
    Callee,
}

impl VtFunctionAssociationMode {
    /// Returns the human-readable label for this mode.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::All        => "ALL",
            Self::NonMatched => "NonMatched",
            Self::Caller     => "Caller",
            Self::Callee     => "Callee",
        }
    }
}

impl std::fmt::Display for VtFunctionAssociationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.display_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_distinct() {
        let variants = [
            VtFunctionAssociationMode::All,
            VtFunctionAssociationMode::NonMatched,
            VtFunctionAssociationMode::Caller,
            VtFunctionAssociationMode::Callee,
        ];
        for i in 0..variants.len() {
            for j in 0..variants.len() {
                if i == j {
                    assert_eq!(variants[i], variants[j]);
                } else {
                    assert_ne!(variants[i], variants[j]);
                }
            }
        }
    }

    #[test]
    fn display_names_match_java() {
        assert_eq!(VtFunctionAssociationMode::All.display_name(), "ALL");
        assert_eq!(VtFunctionAssociationMode::NonMatched.display_name(), "NonMatched");
        assert_eq!(VtFunctionAssociationMode::Caller.display_name(), "Caller");
        assert_eq!(VtFunctionAssociationMode::Callee.display_name(), "Callee");
    }

    #[test]
    fn display_uses_display_name() {
        assert_eq!(VtFunctionAssociationMode::All.to_string(), "ALL");
        assert_eq!(VtFunctionAssociationMode::NonMatched.to_string(), "NonMatched");
        assert_eq!(VtFunctionAssociationMode::Caller.to_string(), "Caller");
        assert_eq!(VtFunctionAssociationMode::Callee.to_string(), "Callee");
    }

    #[test]
    fn copy_and_clone() {
        let m = VtFunctionAssociationMode::Caller;
        let c = m;
        assert_eq!(m, c);
        assert_eq!(m.clone(), m);
    }

    #[test]
    fn hash_in_set() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(VtFunctionAssociationMode::All);
        set.insert(VtFunctionAssociationMode::NonMatched);
        set.insert(VtFunctionAssociationMode::Caller);
        set.insert(VtFunctionAssociationMode::Callee);
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn debug_format() {
        assert_eq!(format!("{:?}", VtFunctionAssociationMode::All), "All");
        assert_eq!(format!("{:?}", VtFunctionAssociationMode::NonMatched), "NonMatched");
        assert_eq!(format!("{:?}", VtFunctionAssociationMode::Caller), "Caller");
        assert_eq!(format!("{:?}", VtFunctionAssociationMode::Callee), "Callee");
    }
}
