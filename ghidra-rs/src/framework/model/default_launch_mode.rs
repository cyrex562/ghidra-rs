use std::fmt;

/// Provides a value which indicates how a default tool launch should be performed.
///
/// Port of `ghidra.framework.model.DefaultLaunchMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DefaultLaunchMode {
    /// Reuse an acceptable running tool.
    ReuseToolMode,
    /// Launch a new default tool.
    NewToolMode,
}

impl DefaultLaunchMode {
    /// The default launch mode.
    pub const DEFAULT: Self = Self::NewToolMode;

    /// Returns the description string for this mode.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ReuseToolMode => "Reuse acceptable running tool",
            Self::NewToolMode => "Launch new default tool",
        }
    }
}

impl fmt::Display for DefaultLaunchMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reuse_tool_mode_string() {
        assert_eq!(DefaultLaunchMode::ReuseToolMode.as_str(), "Reuse acceptable running tool");
    }

    #[test]
    fn test_new_tool_mode_string() {
        assert_eq!(DefaultLaunchMode::NewToolMode.as_str(), "Launch new default tool");
    }

    #[test]
    fn test_default_is_new_tool() {
        assert_eq!(DefaultLaunchMode::DEFAULT, DefaultLaunchMode::NewToolMode);
    }

    #[test]
    fn test_display_reuse_tool() {
        let mode = DefaultLaunchMode::ReuseToolMode;
        assert_eq!(format!("{}", mode), "Reuse acceptable running tool");
    }

    #[test]
    fn test_display_new_tool() {
        let mode = DefaultLaunchMode::NewToolMode;
        assert_eq!(format!("{}", mode), "Launch new default tool");
    }

    #[test]
    fn test_equality() {
        assert_eq!(DefaultLaunchMode::ReuseToolMode, DefaultLaunchMode::ReuseToolMode);
        assert_ne!(DefaultLaunchMode::ReuseToolMode, DefaultLaunchMode::NewToolMode);
    }

    #[test]
    fn test_is_copy() {
        let mode1 = DefaultLaunchMode::NewToolMode;
        let mode2 = mode1;
        assert_eq!(mode1, mode2);
        let _ = mode1;
        let _ = mode2;
    }

    #[test]
    fn test_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(DefaultLaunchMode::ReuseToolMode);
        set.insert(DefaultLaunchMode::NewToolMode);
        assert_eq!(set.len(), 2);
    }
}
