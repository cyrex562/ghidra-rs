use crate::program::model::data::isf::IsfObject;
use crate::program::model::symbol::SourceType;

/// Represents an extended library for SARIF export.
///
/// Mirrors `ExtLibrary` from Ghidra's `sarif.export.extlib` package.
pub struct ExtLibrary {
    pub name: String,
    pub location: String,
    pub source_type: String,
}

impl ExtLibrary {
    /// Creates a new `ExtLibrary` with the given name, location, and source type.
    pub fn new(name: String, location: String, source_type: SourceType) -> Self {
        Self {
            name,
            location,
            source_type: source_type.display_string().to_string(),
        }
    }
}

impl IsfObject for ExtLibrary {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_library_with_fields() {
        let lib = ExtLibrary::new(
            "MyLib".to_string(),
            "/path/to/lib".to_string(),
            SourceType::UserDefined,
        );

        assert_eq!(lib.name, "MyLib");
        assert_eq!(lib.location, "/path/to/lib");
        assert_eq!(lib.source_type, "User Defined");
    }

    #[test]
    fn source_type_converted_to_string() {
        let lib_default = ExtLibrary::new(
            "lib1".to_string(),
            "/path1".to_string(),
            SourceType::Default,
        );
        assert_eq!(lib_default.source_type, "Default");

        let lib_analysis = ExtLibrary::new(
            "lib2".to_string(),
            "/path2".to_string(),
            SourceType::Analysis,
        );
        assert_eq!(lib_analysis.source_type, "Analysis");

        let lib_imported = ExtLibrary::new(
            "lib3".to_string(),
            "/path3".to_string(),
            SourceType::Imported,
        );
        assert_eq!(lib_imported.source_type, "Imported");

        let lib_ai = ExtLibrary::new(
            "lib4".to_string(),
            "/path4".to_string(),
            SourceType::AI,
        );
        assert_eq!(lib_ai.source_type, "AI");
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}
        let lib = ExtLibrary::new(
            "TestLib".to_string(),
            "/test/path".to_string(),
            SourceType::Default,
        );
        accepts_isf_object(&lib);
    }

    #[test]
    fn preserves_name_and_location() {
        let name = "important_lib".to_string();
        let location = "/usr/local/lib/important.so".to_string();
        let lib = ExtLibrary::new(name.clone(), location.clone(), SourceType::Imported);

        assert_eq!(lib.name, name);
        assert_eq!(lib.location, location);
    }
}
