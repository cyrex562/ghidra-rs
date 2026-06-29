/// The kind of program construct covered by a version-tracking association.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VtAssociationType {
    /// The association covers a function.
    Function,
    /// The association covers a data item.
    Data,
}

impl VtAssociationType {
    /// Returns the human-readable label for this type.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Function => "Function",
            Self::Data     => "Data",
        }
    }
}

impl std::fmt::Display for VtAssociationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.display_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_names_match_java() {
        assert_eq!(VtAssociationType::Function.display_name(), "Function");
        assert_eq!(VtAssociationType::Data.display_name(), "Data");
    }

    #[test]
    fn display_uses_display_name() {
        assert_eq!(VtAssociationType::Function.to_string(), "Function");
        assert_eq!(VtAssociationType::Data.to_string(), "Data");
    }

    #[test]
    fn variants_are_distinct() {
        assert_ne!(VtAssociationType::Function, VtAssociationType::Data);
    }

    #[test]
    fn copy_and_clone() {
        let a = VtAssociationType::Function;
        let b = a;
        assert_eq!(a, b);
        assert_eq!(a.clone(), b);
    }
}
