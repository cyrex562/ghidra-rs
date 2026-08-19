/// Thread status value corresponding to JDI `ThreadReference.THREAD_STATUS_RUNNING`.
pub const THREAD_STATUS_RUNNING: i32 = 1;

/// Execution status of the JDI debug target.
///
/// Mirrors `ghidra.dbg.jdi.manager.impl.DebugStatus`. Each variant carries
/// [`should_wait`](DebugStatus::should_wait), [`thread_state`](DebugStatus::thread_state),
/// and [`precedence`](DebugStatus::precedence) semantics from the Java source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DebugStatus {
    NoChange,
    Go,
    StepOver,
    StepInto,
    Break,
    NoDebuggee,
    StepBranch,
    IgnoreEvent,
    RestartRequested,
    OutOfSync,
    WaitInput,
    Timeout,
}

impl DebugStatus {
    /// Bit mask applied to a raw argument to extract the status ordinal.
    pub const MASK: u64 = 0xaf;
    /// Bit flag indicating the debugger is inside a wait operation.
    pub const INSIDE_WAIT: u64 = 0x100000000;
    /// Bit flag indicating a wait operation has timed out.
    pub const WAIT_TIMEOUT: u64 = 0x200000000;

    /// Whether this status means the debugger should wait for the next event.
    pub fn should_wait(self) -> bool {
        match self {
            DebugStatus::NoChange => false,
            DebugStatus::Go => true,
            DebugStatus::StepOver => true,
            DebugStatus::StepInto => true,
            DebugStatus::Break => false,
            // shouldWait is true to handle process creation
            DebugStatus::NoDebuggee => true,
            DebugStatus::StepBranch => true,
            DebugStatus::IgnoreEvent => false,
            DebugStatus::RestartRequested => true,
            DebugStatus::OutOfSync => false,
            DebugStatus::WaitInput => false,
            DebugStatus::Timeout => false,
        }
    }

    /// JDI thread state associated with this status, or `None` if not applicable.
    pub fn thread_state(self) -> Option<i32> {
        match self {
            DebugStatus::Go
            | DebugStatus::StepOver
            | DebugStatus::StepInto
            | DebugStatus::Break => Some(THREAD_STATUS_RUNNING),
            _ => None,
        }
    }

    /// Priority of this status; lower values have higher precedence (0 is highest).
    pub fn precedence(self) -> i32 {
        match self {
            DebugStatus::NoChange => 13,
            DebugStatus::Go => 10,
            DebugStatus::StepOver => 7,
            DebugStatus::StepInto => 5,
            DebugStatus::Break => 0,
            DebugStatus::NoDebuggee => 1,
            DebugStatus::StepBranch => 6,
            DebugStatus::IgnoreEvent => 11,
            DebugStatus::RestartRequested => 12,
            DebugStatus::OutOfSync => 2,
            DebugStatus::WaitInput => 3,
            DebugStatus::Timeout => 4,
        }
    }

    /// Decode a [`DebugStatus`] from a raw argument by masking with [`Self::MASK`].
    ///
    /// Returns `None` if the masked value does not correspond to any variant.
    /// The Java original uses `values()[(int)(argument & MASK)]`, which throws
    /// `ArrayIndexOutOfBoundsException` on an invalid index; here we return `None`.
    pub fn from_argument(argument: u64) -> Option<Self> {
        match argument & Self::MASK {
            0 => Some(DebugStatus::NoChange),
            1 => Some(DebugStatus::Go),
            2 => Some(DebugStatus::StepOver),
            3 => Some(DebugStatus::StepInto),
            4 => Some(DebugStatus::Break),
            5 => Some(DebugStatus::NoDebuggee),
            6 => Some(DebugStatus::StepBranch),
            7 => Some(DebugStatus::IgnoreEvent),
            8 => Some(DebugStatus::RestartRequested),
            9 => Some(DebugStatus::OutOfSync),
            10 => Some(DebugStatus::WaitInput),
            11 => Some(DebugStatus::Timeout),
            _ => None,
        }
    }

    /// Returns `true` if `argument` has the [`Self::INSIDE_WAIT`] flag set.
    pub fn is_inside_wait(argument: u64) -> bool {
        argument & Self::INSIDE_WAIT != 0
    }

    /// Returns `true` if `argument` has the [`Self::WAIT_TIMEOUT`] flag set.
    pub fn is_wait_timeout(argument: u64) -> bool {
        argument & Self::WAIT_TIMEOUT != 0
    }

    /// Returns `added` unchanged; mirrors the Java `update` static method.
    pub fn update(added: DebugStatus) -> DebugStatus {
        added
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_wait_flags() {
        assert!(!DebugStatus::NoChange.should_wait());
        assert!(DebugStatus::Go.should_wait());
        assert!(DebugStatus::StepOver.should_wait());
        assert!(DebugStatus::StepInto.should_wait());
        assert!(!DebugStatus::Break.should_wait());
        assert!(DebugStatus::NoDebuggee.should_wait());
        assert!(DebugStatus::StepBranch.should_wait());
        assert!(!DebugStatus::IgnoreEvent.should_wait());
        assert!(DebugStatus::RestartRequested.should_wait());
        assert!(!DebugStatus::OutOfSync.should_wait());
        assert!(!DebugStatus::WaitInput.should_wait());
        assert!(!DebugStatus::Timeout.should_wait());
    }

    #[test]
    fn test_thread_state() {
        assert_eq!(DebugStatus::Go.thread_state(), Some(THREAD_STATUS_RUNNING));
        assert_eq!(DebugStatus::StepOver.thread_state(), Some(THREAD_STATUS_RUNNING));
        assert_eq!(DebugStatus::StepInto.thread_state(), Some(THREAD_STATUS_RUNNING));
        assert_eq!(DebugStatus::Break.thread_state(), Some(THREAD_STATUS_RUNNING));
        assert_eq!(DebugStatus::NoChange.thread_state(), None);
        assert_eq!(DebugStatus::NoDebuggee.thread_state(), None);
        assert_eq!(DebugStatus::StepBranch.thread_state(), None);
        assert_eq!(DebugStatus::IgnoreEvent.thread_state(), None);
        assert_eq!(DebugStatus::RestartRequested.thread_state(), None);
        assert_eq!(DebugStatus::OutOfSync.thread_state(), None);
        assert_eq!(DebugStatus::WaitInput.thread_state(), None);
        assert_eq!(DebugStatus::Timeout.thread_state(), None);
    }

    #[test]
    fn test_precedence() {
        // Break has highest precedence (0), NoChange has lowest (13)
        assert_eq!(DebugStatus::Break.precedence(), 0);
        assert_eq!(DebugStatus::NoDebuggee.precedence(), 1);
        assert_eq!(DebugStatus::OutOfSync.precedence(), 2);
        assert_eq!(DebugStatus::WaitInput.precedence(), 3);
        assert_eq!(DebugStatus::Timeout.precedence(), 4);
        assert_eq!(DebugStatus::StepInto.precedence(), 5);
        assert_eq!(DebugStatus::StepBranch.precedence(), 6);
        assert_eq!(DebugStatus::StepOver.precedence(), 7);
        assert_eq!(DebugStatus::Go.precedence(), 10);
        assert_eq!(DebugStatus::IgnoreEvent.precedence(), 11);
        assert_eq!(DebugStatus::RestartRequested.precedence(), 12);
        assert_eq!(DebugStatus::NoChange.precedence(), 13);
    }

    #[test]
    fn test_from_argument_ordinals() {
        // Each ordinal 0-11 must round-trip through from_argument
        assert_eq!(DebugStatus::from_argument(0), Some(DebugStatus::NoChange));
        assert_eq!(DebugStatus::from_argument(1), Some(DebugStatus::Go));
        assert_eq!(DebugStatus::from_argument(2), Some(DebugStatus::StepOver));
        assert_eq!(DebugStatus::from_argument(3), Some(DebugStatus::StepInto));
        assert_eq!(DebugStatus::from_argument(4), Some(DebugStatus::Break));
        assert_eq!(DebugStatus::from_argument(5), Some(DebugStatus::NoDebuggee));
        assert_eq!(DebugStatus::from_argument(6), Some(DebugStatus::StepBranch));
        assert_eq!(DebugStatus::from_argument(7), Some(DebugStatus::IgnoreEvent));
        assert_eq!(DebugStatus::from_argument(8), Some(DebugStatus::RestartRequested));
        assert_eq!(DebugStatus::from_argument(9), Some(DebugStatus::OutOfSync));
        assert_eq!(DebugStatus::from_argument(10), Some(DebugStatus::WaitInput));
        assert_eq!(DebugStatus::from_argument(11), Some(DebugStatus::Timeout));
    }

    #[test]
    fn test_from_argument_mask_applied() {
        // Bit 4 (0x10) is not in MASK (0xaf), so it gets stripped; 0x10 | 0 = 0x10 & 0xaf = 0
        assert_eq!(DebugStatus::from_argument(0x10), Some(DebugStatus::NoChange));
        // 0x10 | 1 = 0x11 & 0xaf = 0x01 → Go
        assert_eq!(DebugStatus::from_argument(0x11), Some(DebugStatus::Go));
    }

    #[test]
    fn test_from_argument_out_of_range_returns_none() {
        // 0x20 & 0xaf = 0x20 = 32, which has no variant
        assert_eq!(DebugStatus::from_argument(0x20), None);
    }

    #[test]
    fn test_is_inside_wait() {
        assert!(!DebugStatus::is_inside_wait(0));
        assert!(DebugStatus::is_inside_wait(DebugStatus::INSIDE_WAIT));
        assert!(DebugStatus::is_inside_wait(DebugStatus::INSIDE_WAIT | 5));
        assert!(!DebugStatus::is_inside_wait(DebugStatus::WAIT_TIMEOUT));
    }

    #[test]
    fn test_is_wait_timeout() {
        assert!(!DebugStatus::is_wait_timeout(0));
        assert!(DebugStatus::is_wait_timeout(DebugStatus::WAIT_TIMEOUT));
        assert!(DebugStatus::is_wait_timeout(DebugStatus::WAIT_TIMEOUT | 3));
        assert!(!DebugStatus::is_wait_timeout(DebugStatus::INSIDE_WAIT));
    }

    #[test]
    fn test_update_returns_same() {
        for status in [
            DebugStatus::NoChange,
            DebugStatus::Go,
            DebugStatus::Break,
            DebugStatus::Timeout,
        ] {
            assert_eq!(DebugStatus::update(status), status);
        }
    }

    #[test]
    fn test_constants() {
        assert_eq!(DebugStatus::MASK, 0xaf);
        assert_eq!(DebugStatus::INSIDE_WAIT, 0x100000000);
        assert_eq!(DebugStatus::WAIT_TIMEOUT, 0x200000000);
        assert_eq!(THREAD_STATUS_RUNNING, 1);
    }
}
