use std::fmt;

/// Holds information extracted from a PE export data directory entry.
///
/// This is a pure storage type created during PE header parsing; it does not
/// map back to any PE on-disk data structure directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportInfo {
    address: u64,
    ordinal: u32,
    name: String,
    comment: String,
    forwarded: bool,
}

impl ExportInfo {
    /// Creates a new `ExportInfo`.
    pub fn new(address: u64, ordinal: u32, name: String, comment: String, forwarded: bool) -> Self {
        Self { address, ordinal, name, comment, forwarded }
    }

    /// Returns the adjusted address where the export occurs.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Returns the ordinal value of the export.
    pub fn ordinal(&self) -> u32 {
        self.ordinal
    }

    /// Returns the name of the export.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns extra information about the export.
    pub fn comment(&self) -> &str {
        &self.comment
    }

    /// Returns `true` if this export is forwarded through another export.
    pub fn is_forwarded(&self) -> bool {
        self.forwarded
    }
}

impl fmt::Display for ExportInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} at {:x}", self.ordinal, self.name, self.address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make(address: u64, ordinal: u32, name: &str, comment: &str, forwarded: bool) -> ExportInfo {
        ExportInfo::new(address, ordinal, name.to_string(), comment.to_string(), forwarded)
    }

    #[test]
    fn getters_round_trip() {
        let info = make(0x1000, 5, "MyFunc", "some comment", false);
        assert_eq!(info.address(), 0x1000);
        assert_eq!(info.ordinal(), 5);
        assert_eq!(info.name(), "MyFunc");
        assert_eq!(info.comment(), "some comment");
        assert!(!info.is_forwarded());
    }

    #[test]
    fn forwarded_flag() {
        let info = make(0x2000, 1, "FwdFunc", "", true);
        assert!(info.is_forwarded());
    }

    #[test]
    fn display_matches_java_tostring() {
        let info = make(0x00401000, 3, "ExportedFn", "", false);
        assert_eq!(info.to_string(), "3 ExportedFn at 401000");
    }

    #[test]
    fn display_zero_address() {
        let info = make(0, 0, "", "", false);
        assert_eq!(info.to_string(), "0  at 0");
    }

    #[test]
    fn display_large_address() {
        let info = make(0xdeadbeefcafe, 99, "BigAddr", "", false);
        assert_eq!(info.to_string(), "99 BigAddr at deadbeefcafe");
    }

    #[test]
    fn equality() {
        let a = make(0x1000, 1, "Fn", "cmt", false);
        let b = make(0x1000, 1, "Fn", "cmt", false);
        assert_eq!(a, b);
    }

    #[test]
    fn clone_is_independent() {
        let a = make(0x1000, 1, "Fn", "cmt", false);
        let b = a.clone();
        assert_eq!(a, b);
    }
}
