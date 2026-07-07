use super::guid_info::GuidInfo;
use super::guid_type::GuidType;

/// A GUID paired with a version string.
///
/// Mirrors `ghidra.app.util.datatype.microsoft.VersionedGuidInfo`.
/// Because Rust has no inheritance, `GuidInfo` is held by composition and all
/// delegating accessors are provided explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionedGuidInfo {
    inner: GuidInfo,
    guid_version: String,
    unique_id: String,
}

impl VersionedGuidInfo {
    /// Creates a new `VersionedGuidInfo`. `version` is stored in upper-case.
    pub fn new(
        guid_string: String,
        version: String,
        name: String,
        guid_type: GuidType,
    ) -> Self {
        let guid_version = version.to_uppercase();
        let unique_id = format!("{} {}", guid_string, guid_version);
        let inner = GuidInfo::new(guid_string, name, guid_type);
        Self { inner, guid_version, unique_id }
    }

    /// Returns the version string (upper-cased at construction time).
    pub fn guid_version_string(&self) -> &str {
        &self.guid_version
    }

    /// Returns `"<guid> <VERSION>"` as the unique lookup key.
    ///
    /// Overrides the base `GuidInfo::unique_id_string` behaviour.
    pub fn unique_id_string(&self) -> &str {
        &self.unique_id
    }

    /// Returns the GUID string.
    pub fn guid_string(&self) -> &str {
        self.inner.guid_string()
    }

    /// Returns the symbolic name.
    pub fn name(&self) -> &str {
        self.inner.name()
    }

    /// Returns the GUID category.
    pub fn guid_type(&self) -> GuidType {
        self.inner.guid_type()
    }

    /// Returns a reference to the underlying [`GuidInfo`].
    pub fn as_guid_info(&self) -> &GuidInfo {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::util::datatype::microsoft::guid_type::GuidType;

    fn make_versioned() -> VersionedGuidInfo {
        VersionedGuidInfo::new(
            "6B29FC40-CA47-1067-B31D-00DD010662DA".to_string(),
            "1.0".to_string(),
            "IStorage".to_string(),
            GuidType::Iid,
        )
    }

    #[test]
    fn test_version_uppercased() {
        let v = VersionedGuidInfo::new(
            "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE".to_string(),
            "abc".to_string(),
            "Test".to_string(),
            GuidType::Clsid,
        );
        assert_eq!(v.guid_version_string(), "ABC");
    }

    #[test]
    fn test_unique_id_string_includes_version() {
        let v = make_versioned();
        assert_eq!(
            v.unique_id_string(),
            "6B29FC40-CA47-1067-B31D-00DD010662DA 1.0"
        );
    }

    #[test]
    fn test_unique_id_differs_from_guid_string() {
        let v = make_versioned();
        assert_ne!(v.unique_id_string(), v.guid_string());
    }

    #[test]
    fn test_getters_delegate_to_inner() {
        let v = make_versioned();
        assert_eq!(v.guid_string(), "6B29FC40-CA47-1067-B31D-00DD010662DA");
        assert_eq!(v.name(), "IStorage");
        assert_eq!(v.guid_type(), GuidType::Iid);
    }

    #[test]
    fn test_as_guid_info() {
        let v = make_versioned();
        let info = v.as_guid_info();
        assert_eq!(info.guid_string(), v.guid_string());
        assert_eq!(info.name(), v.name());
    }

    #[test]
    fn test_clone_equality() {
        let v = make_versioned();
        assert_eq!(v, v.clone());
    }

    #[test]
    fn test_debug() {
        let v = make_versioned();
        let s = format!("{:?}", v);
        assert!(s.contains("VersionedGuidInfo"));
    }

    #[test]
    fn test_already_uppercase_version_unchanged() {
        let v = VersionedGuidInfo::new(
            "GUID".to_string(),
            "V2".to_string(),
            "Foo".to_string(),
            GuidType::Syntax,
        );
        assert_eq!(v.guid_version_string(), "V2");
        assert_eq!(v.unique_id_string(), "GUID V2");
    }
}
