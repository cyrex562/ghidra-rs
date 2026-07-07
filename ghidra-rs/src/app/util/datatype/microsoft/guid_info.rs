use super::guid_type::GuidType;

/// Holds a GUID string, its symbolic name, and its category.
///
/// Mirrors `ghidra.app.util.datatype.microsoft.GuidInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuidInfo {
    guid_string: String,
    guid_name: String,
    guid_type: GuidType,
}

impl GuidInfo {
    /// Creates a new `GuidInfo`.
    pub fn new(guid_string: String, name: String, guid_type: GuidType) -> Self {
        Self { guid_string, guid_name: name, guid_type }
    }

    /// Returns the GUID string (e.g. `"6B29FC40-CA47-1067-B31D-00DD010662DA"`).
    pub fn guid_string(&self) -> &str {
        &self.guid_string
    }

    /// Returns the symbolic name associated with this GUID.
    pub fn name(&self) -> &str {
        &self.guid_name
    }

    /// Returns the category of this GUID.
    pub fn guid_type(&self) -> GuidType {
        self.guid_type
    }

    /// Returns the unique identifier string used as a lookup key.
    ///
    /// For plain GUIDs this is the same as [`guid_string`](Self::guid_string).
    /// Subtypes (e.g. `VersionedGuidInfo`) may override this to include version info.
    pub fn unique_id_string(&self) -> &str {
        &self.guid_string
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::util::datatype::microsoft::guid_type::GuidType;

    fn make_info() -> GuidInfo {
        GuidInfo::new(
            "6B29FC40-CA47-1067-B31D-00DD010662DA".to_string(),
            "IStorage".to_string(),
            GuidType::Iid,
        )
    }

    #[test]
    fn test_getters() {
        let info = make_info();
        assert_eq!(info.guid_string(), "6B29FC40-CA47-1067-B31D-00DD010662DA");
        assert_eq!(info.name(), "IStorage");
        assert_eq!(info.guid_type(), GuidType::Iid);
    }

    #[test]
    fn test_unique_id_string_equals_guid_string() {
        let info = make_info();
        assert_eq!(info.unique_id_string(), info.guid_string());
    }

    #[test]
    fn test_clone_equality() {
        let info = make_info();
        let cloned = info.clone();
        assert_eq!(info, cloned);
    }

    #[test]
    fn test_different_guid_types() {
        let clsid = GuidInfo::new("AABB-CC-DD".to_string(), "FooClass".to_string(), GuidType::Clsid);
        let syntax = GuidInfo::new("AABB-CC-DD".to_string(), "FooSyntax".to_string(), GuidType::Syntax);
        assert_ne!(clsid, syntax);
        assert!(clsid.guid_type().has_version() == false);
        assert!(syntax.guid_type().has_version());
    }

    #[test]
    fn test_debug() {
        let info = make_info();
        let s = format!("{:?}", info);
        assert!(s.contains("GuidInfo"));
    }
}
