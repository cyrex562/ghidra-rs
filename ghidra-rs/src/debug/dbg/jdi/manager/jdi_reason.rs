/// Indicates the reason for a thread's state to change, usually only when the thread is stopped.
///
/// This concept is native to JDI. When a thread stops, JDI may communicate the reason, e.g., a
/// breakpoint was hit, or the thread exited. The manager attempts to parse information for the
/// reasons it understands. If JDI provides a reason that is not understood by the manager, then
/// [`Reasons::Unknown`] is given. If no reason is provided, then [`Reasons::None`] is given.
pub trait JdiReason: Send + Sync {
    /// Returns a human-readable description of this reason.
    fn desc(&self) -> &str;
}

/// Reasons other than those given directly by JDI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reasons {
    /// No reason was given.
    None,
    /// Step complete.
    Step,
    /// Target interrupted.
    Interrupt,
    /// Breakpoint hit.
    BreakpointHit,
    /// Watchpoint hit.
    WatchpointHit,
    /// Access watchpoint hit.
    AccessWatchpointHit,
    /// Target resumed.
    Resumed,
    /// A reason was given, but the manager does not understand it.
    Unknown,
}

impl JdiReason for Reasons {
    fn desc(&self) -> &str {
        match self {
            Reasons::None => "No reason",
            Reasons::Step => "Step",
            Reasons::Interrupt => "Interrupt",
            Reasons::BreakpointHit => "Breakpoint",
            Reasons::WatchpointHit => "Watchpoint",
            Reasons::AccessWatchpointHit => "Access Watchpoint",
            Reasons::Resumed => "Resumed",
            Reasons::Unknown => "Unknown",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_implement_jdi_reason() {
        fn accepts(_: &dyn JdiReason) {}
        accepts(&Reasons::None);
        accepts(&Reasons::Step);
        accepts(&Reasons::Interrupt);
        accepts(&Reasons::BreakpointHit);
        accepts(&Reasons::WatchpointHit);
        accepts(&Reasons::AccessWatchpointHit);
        accepts(&Reasons::Resumed);
        accepts(&Reasons::Unknown);
    }

    #[test]
    fn desc_none() {
        assert_eq!(Reasons::None.desc(), "No reason");
    }

    #[test]
    fn desc_step() {
        assert_eq!(Reasons::Step.desc(), "Step");
    }

    #[test]
    fn desc_interrupt() {
        assert_eq!(Reasons::Interrupt.desc(), "Interrupt");
    }

    #[test]
    fn desc_breakpoint_hit() {
        assert_eq!(Reasons::BreakpointHit.desc(), "Breakpoint");
    }

    #[test]
    fn desc_watchpoint_hit() {
        assert_eq!(Reasons::WatchpointHit.desc(), "Watchpoint");
    }

    #[test]
    fn desc_access_watchpoint_hit() {
        assert_eq!(Reasons::AccessWatchpointHit.desc(), "Access Watchpoint");
    }

    #[test]
    fn desc_resumed() {
        assert_eq!(Reasons::Resumed.desc(), "Resumed");
    }

    #[test]
    fn desc_unknown() {
        assert_eq!(Reasons::Unknown.desc(), "Unknown");
    }

    #[test]
    fn reasons_is_copy() {
        let a = Reasons::BreakpointHit;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn reasons_debug() {
        assert_eq!(format!("{:?}", Reasons::None), "None");
        assert_eq!(format!("{:?}", Reasons::Unknown), "Unknown");
    }

    #[test]
    fn via_trait_object() {
        let r: &dyn JdiReason = &Reasons::BreakpointHit;
        assert_eq!(r.desc(), "Breakpoint");
    }
}
