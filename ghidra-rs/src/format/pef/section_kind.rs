/// Values for the `sectionKind` field in a PEF section header.
///
/// Mirrors `ghidra.app.util.bin.format.pef.SectionKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SectionKind {
    /// Code, presumed pure and position independent.
    Code,
    /// Unpacked writeable data.
    UnpackedData,
    /// Packed writeable data.
    PackedData,
    /// Read-only data.
    Constant,
    /// Loader tables.
    Loader,
    /// Reserved for future use.
    Debug,
    /// Intermixed code and writeable data.
    ExecutableData,
    /// Reserved for future use.
    Exception,
    /// Reserved for future use.
    Traceback,
}

impl SectionKind {
    /// Returns the numeric value used in the binary format.
    pub fn value(self) -> u8 {
        match self {
            SectionKind::Code => 0,
            SectionKind::UnpackedData => 1,
            SectionKind::PackedData => 2,
            SectionKind::Constant => 3,
            SectionKind::Loader => 4,
            SectionKind::Debug => 5,
            SectionKind::ExecutableData => 6,
            SectionKind::Exception => 7,
            SectionKind::Traceback => 8,
        }
    }

    /// Returns `true` if this section kind represents an instantiated section.
    pub fn is_instantiated(self) -> bool {
        match self {
            SectionKind::Code
            | SectionKind::UnpackedData
            | SectionKind::PackedData
            | SectionKind::Constant
            | SectionKind::ExecutableData => true,
            SectionKind::Loader
            | SectionKind::Debug
            | SectionKind::Exception
            | SectionKind::Traceback => false,
        }
    }

    /// Returns the `SectionKind` corresponding to the given raw value.
    ///
    /// Returns `None` if the value does not match any known kind.
    pub fn from_value(value: u8) -> Option<Self> {
        match value {
            0 => Some(SectionKind::Code),
            1 => Some(SectionKind::UnpackedData),
            2 => Some(SectionKind::PackedData),
            3 => Some(SectionKind::Constant),
            4 => Some(SectionKind::Loader),
            5 => Some(SectionKind::Debug),
            6 => Some(SectionKind::ExecutableData),
            7 => Some(SectionKind::Exception),
            8 => Some(SectionKind::Traceback),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_match_java_source() {
        assert_eq!(SectionKind::Code.value(), 0);
        assert_eq!(SectionKind::UnpackedData.value(), 1);
        assert_eq!(SectionKind::PackedData.value(), 2);
        assert_eq!(SectionKind::Constant.value(), 3);
        assert_eq!(SectionKind::Loader.value(), 4);
        assert_eq!(SectionKind::Debug.value(), 5);
        assert_eq!(SectionKind::ExecutableData.value(), 6);
        assert_eq!(SectionKind::Exception.value(), 7);
        assert_eq!(SectionKind::Traceback.value(), 8);
    }

    #[test]
    fn instantiated_flags_match_java_source() {
        assert!(SectionKind::Code.is_instantiated());
        assert!(SectionKind::UnpackedData.is_instantiated());
        assert!(SectionKind::PackedData.is_instantiated());
        assert!(SectionKind::Constant.is_instantiated());
        assert!(!SectionKind::Loader.is_instantiated());
        assert!(!SectionKind::Debug.is_instantiated());
        assert!(SectionKind::ExecutableData.is_instantiated());
        assert!(!SectionKind::Exception.is_instantiated());
        assert!(!SectionKind::Traceback.is_instantiated());
    }

    #[test]
    fn from_value_round_trips_all_variants() {
        for v in 0u8..=8 {
            let kind = SectionKind::from_value(v).expect("known value");
            assert_eq!(kind.value(), v);
        }
    }

    #[test]
    fn from_value_returns_none_for_unknown() {
        assert!(SectionKind::from_value(9).is_none());
        assert!(SectionKind::from_value(255).is_none());
    }
}
