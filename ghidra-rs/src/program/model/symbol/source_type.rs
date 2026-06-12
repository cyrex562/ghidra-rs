#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SourceType {
    // Ord matches the declared order by default, but we'll override it manually to match Ghidra's priority
    Default = 0,
    Analysis = 1,
    AI = 2,
    Imported = 3,
    UserDefined = 4,
}

impl SourceType {
    pub fn get_source_type(storage_id: i32) -> Result<Self, String> {
        Self::from_storage_id(storage_id)
            .ok_or_else(|| format!("SourceType storage ID not defined: {}", storage_id))
    }

    pub fn display_string(&self) -> &'static str {
        match self {
            SourceType::Default => "Default",
            SourceType::Analysis => "Analysis",
            SourceType::AI => "AI",
            SourceType::Imported => "Imported",
            SourceType::UserDefined => "User Defined",
        }
    }

    pub fn priority(&self) -> i32 {
        match self {
            SourceType::Default => 1,
            SourceType::Analysis => 2,
            SourceType::AI => 2,
            SourceType::Imported => 3,
            SourceType::UserDefined => 4,
        }
    }

    pub fn storage_id(&self) -> i32 {
        match self {
            SourceType::Analysis => 0,
            SourceType::UserDefined => 1,
            SourceType::Default => 2,
            SourceType::Imported => 3,
            SourceType::AI => 4,
        }
    }

    pub fn from_storage_id(id: i32) -> Option<Self> {
        match id {
            0 => Some(SourceType::Analysis),
            1 => Some(SourceType::UserDefined),
            2 => Some(SourceType::Default),
            3 => Some(SourceType::Imported),
            4 => Some(SourceType::AI),
            _ => None,
        }
    }

    pub fn is_lower_priority_than(&self, other: &Self) -> bool {
        self.priority() < other.priority()
    }

    pub fn is_higher_priority_than(&self, other: &Self) -> bool {
        self.priority() > other.priority()
    }

    pub fn is_higher_or_equal_priority_than(&self, other: &Self) -> bool {
        self.priority() >= other.priority()
    }

    pub fn is_lower_or_equal_priority_than(&self, other: &Self) -> bool {
        self.priority() <= other.priority()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_ids_match_java_persistent_ids() {
        assert_eq!(SourceType::Analysis.storage_id(), 0);
        assert_eq!(SourceType::UserDefined.storage_id(), 1);
        assert_eq!(SourceType::Default.storage_id(), 2);
        assert_eq!(SourceType::Imported.storage_id(), 3);
        assert_eq!(SourceType::AI.storage_id(), 4);

        assert_eq!(SourceType::get_source_type(0), Ok(SourceType::Analysis));
        assert_eq!(SourceType::get_source_type(1), Ok(SourceType::UserDefined));
        assert_eq!(SourceType::get_source_type(2), Ok(SourceType::Default));
        assert_eq!(SourceType::get_source_type(3), Ok(SourceType::Imported));
        assert_eq!(SourceType::get_source_type(4), Ok(SourceType::AI));
        assert!(SourceType::get_source_type(5).is_err());
    }

    #[test]
    fn display_strings_match_java() {
        assert_eq!(SourceType::Default.display_string(), "Default");
        assert_eq!(SourceType::Analysis.display_string(), "Analysis");
        assert_eq!(SourceType::AI.display_string(), "AI");
        assert_eq!(SourceType::Imported.display_string(), "Imported");
        assert_eq!(SourceType::UserDefined.display_string(), "User Defined");
    }

    #[test]
    fn priority_comparisons_match_java() {
        assert!(SourceType::UserDefined.is_higher_priority_than(&SourceType::Imported));
        assert!(SourceType::Imported.is_higher_priority_than(&SourceType::Analysis));
        assert!(!SourceType::Analysis.is_higher_priority_than(&SourceType::AI));
        assert!(SourceType::Analysis.is_higher_or_equal_priority_than(&SourceType::AI));
        assert!(SourceType::Default.is_lower_priority_than(&SourceType::Analysis));
        assert!(SourceType::Default.is_lower_or_equal_priority_than(&SourceType::Default));
    }
}
