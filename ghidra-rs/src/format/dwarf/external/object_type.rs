/// Categorizes the type of an external debug object.
///
/// Maps to `ghidra.app.util.bin.format.dwarf.external.ObjectType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectType {
    DebugInfo,
    Executable,
    Source,
}

impl ObjectType {
    /// Returns the lowercase string name used in path construction.
    pub fn path_string(self) -> &'static str {
        match self {
            ObjectType::DebugInfo => "debuginfo",
            ObjectType::Executable => "executable",
            ObjectType::Source => "source",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_strings_match_java() {
        assert_eq!(ObjectType::DebugInfo.path_string(), "debuginfo");
        assert_eq!(ObjectType::Executable.path_string(), "executable");
        assert_eq!(ObjectType::Source.path_string(), "source");
    }

    #[test]
    fn all_variants_are_distinct() {
        let variants = [ObjectType::DebugInfo, ObjectType::Executable, ObjectType::Source];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn clone_and_copy() {
        let original = ObjectType::Executable;
        let copied = original;
        assert_eq!(original, copied);
    }

    #[test]
    fn debug_format() {
        assert_eq!(format!("{:?}", ObjectType::DebugInfo), "DebugInfo");
        assert_eq!(format!("{:?}", ObjectType::Executable), "Executable");
        assert_eq!(format!("{:?}", ObjectType::Source), "Source");
    }
}
