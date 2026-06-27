/// The category of a GUID entry, corresponding to a specific archive file.
///
/// Mirrors `ghidra.app.util.datatype.microsoft.GuidUtil.GuidType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GuidType {
    Clsid,
    Iid,
    Guid,
    Syntax,
}

impl GuidType {
    /// Returns the archive filename associated with this GUID type.
    pub fn filename(self) -> &'static str {
        match self {
            GuidType::Clsid => "clsids.txt",
            GuidType::Iid => "iids.txt",
            GuidType::Guid => "guids.txt",
            GuidType::Syntax => "syntaxes.txt",
        }
    }

    /// Returns `true` if GUIDs of this type include a version component.
    pub fn has_version(self) -> bool {
        matches!(self, GuidType::Syntax)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filenames() {
        assert_eq!(GuidType::Clsid.filename(), "clsids.txt");
        assert_eq!(GuidType::Iid.filename(), "iids.txt");
        assert_eq!(GuidType::Guid.filename(), "guids.txt");
        assert_eq!(GuidType::Syntax.filename(), "syntaxes.txt");
    }

    #[test]
    fn test_has_version() {
        assert!(!GuidType::Clsid.has_version());
        assert!(!GuidType::Iid.has_version());
        assert!(!GuidType::Guid.has_version());
        assert!(GuidType::Syntax.has_version());
    }

    #[test]
    fn test_copy() {
        let t = GuidType::Iid;
        let copy = t;
        assert_eq!(t, copy);
    }

    #[test]
    fn test_debug() {
        let s = format!("{:?}", GuidType::Clsid);
        assert!(s.contains("Clsid"));
    }
}
