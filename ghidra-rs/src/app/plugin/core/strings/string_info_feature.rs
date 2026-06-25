#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StringInfoFeature {
    CodecError,
    NonStdCtrlChars,
}

impl StringInfoFeature {
    pub fn as_str(&self) -> &'static str {
        match self {
            StringInfoFeature::CodecError => "CODEC_ERROR",
            StringInfoFeature::NonStdCtrlChars => "NON_STD_CTRL_CHARS",
        }
    }
}

impl std::fmt::Display for StringInfoFeature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_codec_error() {
        let variant = StringInfoFeature::CodecError;
        assert_eq!(variant.as_str(), "CODEC_ERROR");
        assert_eq!(variant.to_string(), "CODEC_ERROR");
    }

    #[test]
    fn test_non_std_ctrl_chars() {
        let variant = StringInfoFeature::NonStdCtrlChars;
        assert_eq!(variant.as_str(), "NON_STD_CTRL_CHARS");
        assert_eq!(variant.to_string(), "NON_STD_CTRL_CHARS");
    }

    #[test]
    fn test_enum_properties() {
        let codec_error = StringInfoFeature::CodecError;
        let non_std = StringInfoFeature::NonStdCtrlChars;

        assert_eq!(codec_error, codec_error);
        assert_ne!(codec_error, non_std);

        assert_eq!(format!("{:?}", codec_error), "CodecError");
        assert_eq!(format!("{:?}", non_std), "NonStdCtrlChars");
    }

    #[test]
    fn test_hash() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(StringInfoFeature::CodecError);
        set.insert(StringInfoFeature::NonStdCtrlChars);

        assert_eq!(set.len(), 2);
        assert!(set.contains(&StringInfoFeature::CodecError));
    }

    #[test]
    fn test_clone_and_copy() {
        let original = StringInfoFeature::CodecError;
        let cloned = original.clone();
        let copied = original;

        assert_eq!(cloned, original);
        assert_eq!(copied, original);
    }
}
