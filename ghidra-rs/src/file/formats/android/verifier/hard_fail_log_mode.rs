/// Log verbosity level for hard-fail verification events, mirroring
/// `ghidra.file.formats.android.verifier.HardFailLogMode`.
///
/// Source:
/// <https://android.googlesource.com/platform/art/+/master/runtime/verifier/verifier_enums.h>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardFailLogMode {
    LogNone,
    LogVerbose,
    LogWarning,
    LogInternalFatal,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_are_distinct() {
        assert_ne!(HardFailLogMode::LogNone, HardFailLogMode::LogVerbose);
        assert_ne!(HardFailLogMode::LogVerbose, HardFailLogMode::LogWarning);
        assert_ne!(HardFailLogMode::LogWarning, HardFailLogMode::LogInternalFatal);
        assert_ne!(HardFailLogMode::LogNone, HardFailLogMode::LogInternalFatal);
    }

    #[test]
    fn variants_are_copy() {
        let m = HardFailLogMode::LogWarning;
        let _m2 = m;
        let _m3 = m;
    }

    #[test]
    fn variants_debug() {
        assert_eq!(format!("{:?}", HardFailLogMode::LogNone), "LogNone");
        assert_eq!(format!("{:?}", HardFailLogMode::LogVerbose), "LogVerbose");
        assert_eq!(format!("{:?}", HardFailLogMode::LogWarning), "LogWarning");
        assert_eq!(format!("{:?}", HardFailLogMode::LogInternalFatal), "LogInternalFatal");
    }

    #[test]
    fn variants_clone() {
        let m = HardFailLogMode::LogVerbose;
        assert_eq!(m.clone(), HardFailLogMode::LogVerbose);
    }
}
