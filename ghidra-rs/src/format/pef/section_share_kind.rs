/// Values for the `shareKind` field in a PEF section header.
///
/// Mirrors `ghidra.app.util.bin.format.pef.SectionShareKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SectionShareKind {
    /// Shared within a process; a fresh copy is created for different processes.
    ProcessShare,
    /// Shared between all processes in the system.
    GlobalShare,
    /// Shared between all processes, but protected: read/write in privileged mode,
    /// read-only in user mode.
    ProtectedShare,
}

impl SectionShareKind {
    /// Returns the numeric value used in the binary format.
    pub fn value(self) -> u8 {
        match self {
            SectionShareKind::ProcessShare => 1,
            SectionShareKind::GlobalShare => 4,
            SectionShareKind::ProtectedShare => 5,
        }
    }

    /// Returns the `SectionShareKind` corresponding to the given raw value.
    ///
    /// Returns `None` if the value does not match any known kind.
    pub fn from_value(value: u8) -> Option<Self> {
        match value {
            1 => Some(SectionShareKind::ProcessShare),
            4 => Some(SectionShareKind::GlobalShare),
            5 => Some(SectionShareKind::ProtectedShare),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_match_java_source() {
        assert_eq!(SectionShareKind::ProcessShare.value(), 1);
        assert_eq!(SectionShareKind::GlobalShare.value(), 4);
        assert_eq!(SectionShareKind::ProtectedShare.value(), 5);
    }

    #[test]
    fn from_value_round_trips_all_variants() {
        for &v in &[1u8, 4, 5] {
            let kind = SectionShareKind::from_value(v).expect("known value");
            assert_eq!(kind.value(), v);
        }
    }

    #[test]
    fn from_value_returns_none_for_unknown() {
        assert!(SectionShareKind::from_value(0).is_none());
        assert!(SectionShareKind::from_value(2).is_none());
        assert!(SectionShareKind::from_value(3).is_none());
        assert!(SectionShareKind::from_value(6).is_none());
        assert!(SectionShareKind::from_value(255).is_none());
    }
}
