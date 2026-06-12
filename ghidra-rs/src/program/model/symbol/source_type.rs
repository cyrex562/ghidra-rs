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
}
