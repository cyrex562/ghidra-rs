use std::fmt;

/// The type of JDI breakpoint.
///
/// Mirrors `JdiBreakpointType` from `ghidra.dbg.jdi.manager.breakpoint`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JdiBreakpointType {
    Breakpoint,
    AccessWatchpoint,
    ModificationWatchpoint,
    Other,
}

impl JdiBreakpointType {
    /// Returns the canonical string name used in JDI breakpoint information blocks.
    pub fn name(self) -> &'static str {
        match self {
            Self::Breakpoint => "breakpoint",
            // NOTE: "watchpont" (missing 'i') is the original Java spelling — preserved for parity.
            Self::AccessWatchpoint => "access watchpont",
            Self::ModificationWatchpoint => "modification watchpoint",
            Self::Other => "<OTHER>",
        }
    }

    /// Returns true for access and modification watchpoints.
    pub fn is_watchpoint(self) -> bool {
        matches!(self, Self::AccessWatchpoint | Self::ModificationWatchpoint)
    }

    /// Parse a breakpoint type from its string name.
    ///
    /// Returns [`JdiBreakpointType::Other`] if the string is not recognized.
    pub fn from_str(s: &str) -> Self {
        match s {
            "breakpoint" => Self::Breakpoint,
            "access watchpont" => Self::AccessWatchpoint,
            "modification watchpoint" => Self::ModificationWatchpoint,
            _ => Self::Other,
        }
    }
}

impl fmt::Display for JdiBreakpointType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn breakpoint_name() {
        assert_eq!(JdiBreakpointType::Breakpoint.name(), "breakpoint");
    }

    #[test]
    fn access_watchpoint_name() {
        assert_eq!(JdiBreakpointType::AccessWatchpoint.name(), "access watchpont");
    }

    #[test]
    fn modification_watchpoint_name() {
        assert_eq!(
            JdiBreakpointType::ModificationWatchpoint.name(),
            "modification watchpoint"
        );
    }

    #[test]
    fn other_name() {
        assert_eq!(JdiBreakpointType::Other.name(), "<OTHER>");
    }

    #[test]
    fn is_watchpoint_false_for_breakpoint() {
        assert!(!JdiBreakpointType::Breakpoint.is_watchpoint());
    }

    #[test]
    fn is_watchpoint_false_for_other() {
        assert!(!JdiBreakpointType::Other.is_watchpoint());
    }

    #[test]
    fn is_watchpoint_true_for_access() {
        assert!(JdiBreakpointType::AccessWatchpoint.is_watchpoint());
    }

    #[test]
    fn is_watchpoint_true_for_modification() {
        assert!(JdiBreakpointType::ModificationWatchpoint.is_watchpoint());
    }

    #[test]
    fn from_str_breakpoint() {
        assert_eq!(
            JdiBreakpointType::from_str("breakpoint"),
            JdiBreakpointType::Breakpoint
        );
    }

    #[test]
    fn from_str_access_watchpoint() {
        assert_eq!(
            JdiBreakpointType::from_str("access watchpont"),
            JdiBreakpointType::AccessWatchpoint
        );
    }

    #[test]
    fn from_str_modification_watchpoint() {
        assert_eq!(
            JdiBreakpointType::from_str("modification watchpoint"),
            JdiBreakpointType::ModificationWatchpoint
        );
    }

    #[test]
    fn from_str_unknown_returns_other() {
        assert_eq!(
            JdiBreakpointType::from_str("unknown"),
            JdiBreakpointType::Other
        );
    }

    #[test]
    fn from_str_empty_returns_other() {
        assert_eq!(
            JdiBreakpointType::from_str(""),
            JdiBreakpointType::Other
        );
    }

    #[test]
    fn display_matches_name() {
        let ty = JdiBreakpointType::Breakpoint;
        assert_eq!(format!("{ty}"), ty.name());
    }

    #[test]
    fn round_trip_breakpoint() {
        let ty = JdiBreakpointType::Breakpoint;
        assert_eq!(JdiBreakpointType::from_str(ty.name()), ty);
    }

    #[test]
    fn round_trip_modification_watchpoint() {
        let ty = JdiBreakpointType::ModificationWatchpoint;
        assert_eq!(JdiBreakpointType::from_str(ty.name()), ty);
    }

    #[test]
    fn is_copy() {
        let a = JdiBreakpointType::Breakpoint;
        let b = a;
        assert_eq!(a, b);
    }
}
