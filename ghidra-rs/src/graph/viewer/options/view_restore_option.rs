/// Controls how a graph view is restored when revisited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ViewRestoreOption {
    StartFullyZoomedOut,
    StartFullyZoomedIn,
    RememberSettings,
}

impl ViewRestoreOption {
    pub fn display_name(self) -> &'static str {
        match self {
            Self::StartFullyZoomedOut => "Start Fully Zoomed Out",
            Self::StartFullyZoomedIn => "Start Fully Zoomed In",
            Self::RememberSettings => "Remember User Settings",
        }
    }
}

impl std::fmt::Display for ViewRestoreOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.display_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_start_fully_zoomed_out() {
        assert_eq!(
            ViewRestoreOption::StartFullyZoomedOut.to_string(),
            "Start Fully Zoomed Out"
        );
    }

    #[test]
    fn test_display_start_fully_zoomed_in() {
        assert_eq!(
            ViewRestoreOption::StartFullyZoomedIn.to_string(),
            "Start Fully Zoomed In"
        );
    }

    #[test]
    fn test_display_remember_settings() {
        assert_eq!(
            ViewRestoreOption::RememberSettings.to_string(),
            "Remember User Settings"
        );
    }

    #[test]
    fn test_copy() {
        let a = ViewRestoreOption::RememberSettings;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn test_equality() {
        assert_eq!(
            ViewRestoreOption::StartFullyZoomedOut,
            ViewRestoreOption::StartFullyZoomedOut
        );
        assert_ne!(
            ViewRestoreOption::StartFullyZoomedOut,
            ViewRestoreOption::StartFullyZoomedIn
        );
    }

    #[test]
    fn test_debug() {
        assert_eq!(
            format!("{:?}", ViewRestoreOption::StartFullyZoomedOut),
            "StartFullyZoomedOut"
        );
        assert_eq!(
            format!("{:?}", ViewRestoreOption::RememberSettings),
            "RememberSettings"
        );
    }

    #[test]
    fn test_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(ViewRestoreOption::StartFullyZoomedOut);
        set.insert(ViewRestoreOption::StartFullyZoomedIn);
        set.insert(ViewRestoreOption::RememberSettings);
        assert_eq!(set.len(), 3);
        set.insert(ViewRestoreOption::StartFullyZoomedOut);
        assert_eq!(set.len(), 3);
    }
}
