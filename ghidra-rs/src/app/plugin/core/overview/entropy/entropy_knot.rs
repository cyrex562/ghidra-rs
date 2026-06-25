use super::entropy_record::EntropyRecord;
use std::fmt;

/// Enum for defining known entropy ranges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntropyKnot {
    None,
    X86,
    Arm,
    Thumb,
    PowerPC,
    ASCII,
    Compressed,
    UTF16,
}

impl EntropyKnot {
    /// Returns the label for this entropy knot.
    pub fn label(&self) -> &'static str {
        match self {
            EntropyKnot::None => "None",
            EntropyKnot::X86 => "x86 code",
            EntropyKnot::Arm => "ARM code",
            EntropyKnot::Thumb => "THUMB code",
            EntropyKnot::PowerPC => "PowerPC code",
            EntropyKnot::ASCII => "ASCII strings",
            EntropyKnot::Compressed => "Compressed",
            EntropyKnot::UTF16 => "Unicode UTF16",
        }
    }

    /// Returns the entropy record for this knot, if one exists.
    pub fn record(&self) -> Option<EntropyRecord> {
        match self {
            EntropyKnot::None => None,
            EntropyKnot::X86 => Some(EntropyRecord::new("x86", 5.94, 0.4)),
            EntropyKnot::Arm => Some(EntropyRecord::new("arm", 5.1252, 0.51)),
            EntropyKnot::Thumb => Some(EntropyRecord::new("thumb", 6.2953, 0.5)),
            EntropyKnot::PowerPC => Some(EntropyRecord::new("powerpc", 5.6674, 0.52)),
            EntropyKnot::ASCII => Some(EntropyRecord::new("ascii", 4.7, 0.5)),
            EntropyKnot::Compressed => Some(EntropyRecord::new("compressed", 8.0, 0.5)),
            EntropyKnot::UTF16 => Some(EntropyRecord::new("utf16", 3.21, 0.2)),
        }
    }
}

impl fmt::Display for EntropyKnot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_none_label() {
        assert_eq!(EntropyKnot::None.label(), "None");
    }

    #[test]
    fn test_x86_label() {
        assert_eq!(EntropyKnot::X86.label(), "x86 code");
    }

    #[test]
    fn test_arm_label() {
        assert_eq!(EntropyKnot::Arm.label(), "ARM code");
    }

    #[test]
    fn test_thumb_label() {
        assert_eq!(EntropyKnot::Thumb.label(), "THUMB code");
    }

    #[test]
    fn test_powerpc_label() {
        assert_eq!(EntropyKnot::PowerPC.label(), "PowerPC code");
    }

    #[test]
    fn test_ascii_label() {
        assert_eq!(EntropyKnot::ASCII.label(), "ASCII strings");
    }

    #[test]
    fn test_compressed_label() {
        assert_eq!(EntropyKnot::Compressed.label(), "Compressed");
    }

    #[test]
    fn test_utf16_label() {
        assert_eq!(EntropyKnot::UTF16.label(), "Unicode UTF16");
    }

    #[test]
    fn test_none_record() {
        assert_eq!(EntropyKnot::None.record(), None);
    }

    #[test]
    fn test_x86_record() {
        let record = EntropyKnot::X86.record();
        assert!(record.is_some());
        let r = record.unwrap();
        assert_eq!(r.name, "x86");
        assert_eq!(r.center, 5.94);
        assert_eq!(r.width, 0.4);
    }

    #[test]
    fn test_arm_record() {
        let record = EntropyKnot::Arm.record();
        assert!(record.is_some());
        let r = record.unwrap();
        assert_eq!(r.name, "arm");
        assert_eq!(r.center, 5.1252);
        assert_eq!(r.width, 0.51);
    }

    #[test]
    fn test_thumb_record() {
        let record = EntropyKnot::Thumb.record();
        assert!(record.is_some());
        let r = record.unwrap();
        assert_eq!(r.name, "thumb");
        assert_eq!(r.center, 6.2953);
        assert_eq!(r.width, 0.5);
    }

    #[test]
    fn test_powerpc_record() {
        let record = EntropyKnot::PowerPC.record();
        assert!(record.is_some());
        let r = record.unwrap();
        assert_eq!(r.name, "powerpc");
        assert_eq!(r.center, 5.6674);
        assert_eq!(r.width, 0.52);
    }

    #[test]
    fn test_ascii_record() {
        let record = EntropyKnot::ASCII.record();
        assert!(record.is_some());
        let r = record.unwrap();
        assert_eq!(r.name, "ascii");
        assert_eq!(r.center, 4.7);
        assert_eq!(r.width, 0.5);
    }

    #[test]
    fn test_compressed_record() {
        let record = EntropyKnot::Compressed.record();
        assert!(record.is_some());
        let r = record.unwrap();
        assert_eq!(r.name, "compressed");
        assert_eq!(r.center, 8.0);
        assert_eq!(r.width, 0.5);
    }

    #[test]
    fn test_utf16_record() {
        let record = EntropyKnot::UTF16.record();
        assert!(record.is_some());
        let r = record.unwrap();
        assert_eq!(r.name, "utf16");
        assert_eq!(r.center, 3.21);
        assert_eq!(r.width, 0.2);
    }

    #[test]
    fn test_display_all_variants() {
        let variants = [
            EntropyKnot::None,
            EntropyKnot::X86,
            EntropyKnot::Arm,
            EntropyKnot::Thumb,
            EntropyKnot::PowerPC,
            EntropyKnot::ASCII,
            EntropyKnot::Compressed,
            EntropyKnot::UTF16,
        ];

        for variant in variants.iter() {
            let label = variant.label();
            assert!(!label.is_empty());
            assert_eq!(variant.to_string(), label);
        }
    }

    #[test]
    fn test_equality() {
        assert_eq!(EntropyKnot::X86, EntropyKnot::X86);
        assert_ne!(EntropyKnot::X86, EntropyKnot::Arm);
    }

    #[test]
    fn test_clone_and_copy() {
        let knot = EntropyKnot::X86;
        let cloned = knot;
        assert_eq!(knot, cloned);
    }
}
