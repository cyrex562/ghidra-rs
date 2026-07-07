/// Instantiation mode for DomainObject implementations and internal storage adapters.
///
/// Port of `ghidra.framework.data.OpenMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    /// Creating new domain object.
    Create,
    /// Domain object opened as an immutable instance.
    Immutable,
    /// Domain object opened for modification.
    Update,
    /// Domain object opened for modification with data upgrade permitted.
    Upgrade,
}

impl OpenMode {
    /// Returns the string representation of this open mode.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Create => "CREATE",
            Self::Immutable => "IMMUTABLE",
            Self::Update => "UPDATE",
            Self::Upgrade => "UPGRADE",
        }
    }
}

impl std::fmt::Display for OpenMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_variant() {
        let mode = OpenMode::Create;
        assert_eq!(mode.as_str(), "CREATE");
        assert_eq!(mode.to_string(), "CREATE");
    }

    #[test]
    fn test_immutable_variant() {
        let mode = OpenMode::Immutable;
        assert_eq!(mode.as_str(), "IMMUTABLE");
        assert_eq!(mode.to_string(), "IMMUTABLE");
    }

    #[test]
    fn test_update_variant() {
        let mode = OpenMode::Update;
        assert_eq!(mode.as_str(), "UPDATE");
        assert_eq!(mode.to_string(), "UPDATE");
    }

    #[test]
    fn test_upgrade_variant() {
        let mode = OpenMode::Upgrade;
        assert_eq!(mode.as_str(), "UPGRADE");
        assert_eq!(mode.to_string(), "UPGRADE");
    }

    #[test]
    fn test_debug_format() {
        assert_eq!(format!("{:?}", OpenMode::Create), "Create");
        assert_eq!(format!("{:?}", OpenMode::Immutable), "Immutable");
        assert_eq!(format!("{:?}", OpenMode::Update), "Update");
        assert_eq!(format!("{:?}", OpenMode::Upgrade), "Upgrade");
    }

    #[test]
    fn test_equality() {
        assert_eq!(OpenMode::Create, OpenMode::Create);
        assert_ne!(OpenMode::Create, OpenMode::Immutable);
    }

    #[test]
    fn test_copy_trait() {
        let mode = OpenMode::Create;
        let _mode2 = mode;
        let _mode3 = mode;
    }
}
