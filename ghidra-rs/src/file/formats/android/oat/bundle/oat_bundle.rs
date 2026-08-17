/// A fictitious interface to locate, open, and store all of the files related to Android OAT/ART.
///
/// This trait represents the abstract interface for accessing various Android runtime file headers
/// (OAT, ART, VDEX, and DEX) from a bundle that contains multiple related files.
pub trait OatBundle: Send + Sync {
    /// Closes the bundle and releases any resources.
    fn close(&self);

    /// Returns the corresponding OAT header.
    fn get_oat_header(&self) -> Option<&dyn std::any::Any>;

    /// Returns the corresponding ART header.
    fn get_art_header(&self) -> Option<&dyn std::any::Any>;

    /// Returns the corresponding VDEX header.
    fn get_vdex_header(&self) -> Option<&dyn std::any::Any>;

    /// Returns the corresponding DEX headers.
    fn get_dex_headers(&self) -> Vec<&dyn std::any::Any>;

    /// Returns the DEX header with the specified checksum.
    fn get_dex_header_by_checksum(&self, checksum: i32) -> Option<&dyn std::any::Any>;
}

/// Header type enumeration for different Android runtime file formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HeaderType {
    Art,
    Cdex,
    Dex,
    Vdex,
}

impl HeaderType {
    pub fn as_str(&self) -> &'static str {
        match self {
            HeaderType::Art => "ART",
            HeaderType::Cdex => "CDEX",
            HeaderType::Dex => "DEX",
            HeaderType::Vdex => "VDEX",
        }
    }
}

impl std::fmt::Display for HeaderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// File extension constants for Android runtime files.
pub mod file_extensions {
    pub const APK: &str = ".apk";
    pub const ART: &str = ".art";
    pub const CLASSES: &str = "classes";
    pub const CDEX: &str = "cdex";
    pub const DEX: &str = ".dex";
    pub const JAR: &str = ".jar";
    pub const OAT: &str = ".oat";
    pub const ODEX: &str = ".odex";
    pub const VDEX: &str = ".vdex";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_type_display() {
        assert_eq!(HeaderType::Art.as_str(), "ART");
        assert_eq!(HeaderType::Cdex.as_str(), "CDEX");
        assert_eq!(HeaderType::Dex.as_str(), "DEX");
        assert_eq!(HeaderType::Vdex.as_str(), "VDEX");
    }

    #[test]
    fn test_file_extensions() {
        assert_eq!(file_extensions::APK, ".apk");
        assert_eq!(file_extensions::ART, ".art");
        assert_eq!(file_extensions::CLASSES, "classes");
        assert_eq!(file_extensions::CDEX, "cdex");
        assert_eq!(file_extensions::DEX, ".dex");
        assert_eq!(file_extensions::JAR, ".jar");
        assert_eq!(file_extensions::OAT, ".oat");
        assert_eq!(file_extensions::ODEX, ".odex");
        assert_eq!(file_extensions::VDEX, ".vdex");
    }

    #[test]
    fn test_header_type_to_string() {
        assert_eq!(HeaderType::Art.to_string(), "ART");
        assert_eq!(HeaderType::Dex.to_string(), "DEX");
    }
}
