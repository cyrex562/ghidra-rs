use crate::sarif::SarifSchema210;
use anyhow::Result;
use std::path::Path;

/// Trait for reading SARIF 2.1.0 data from a file or a string.
/// Mirrors the Java interface `sarif.io.SarifIO`.
pub trait SarifIo {
    /// Parse a SARIF document from a file on disk.
    /// Mirrors `readSarif(File file)`.
    fn read_sarif_from_file(&self, path: &Path) -> Result<SarifSchema210>;

    /// Parse a SARIF document from a JSON string.
    /// Mirrors `readSarif(String str)`.
    fn read_sarif_from_str(&self, s: &str) -> Result<SarifSchema210>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    struct JsonSarifReader;

    impl SarifIo for JsonSarifReader {
        fn read_sarif_from_file(&self, path: &Path) -> Result<SarifSchema210> {
            let content = std::fs::read_to_string(path)?;
            self.read_sarif_from_str(&content)
        }

        fn read_sarif_from_str(&self, s: &str) -> Result<SarifSchema210> {
            let value: serde_json::Value = serde_json::from_str(s)?;
            Ok(SarifSchema210::new(value))
        }
    }

    #[test]
    fn test_read_sarif_from_str_valid() {
        let reader = JsonSarifReader;
        let json = r#"{"version":"2.1.0","runs":[]}"#;
        let result = reader.read_sarif_from_str(json).unwrap();
        assert_eq!(result.as_value()["version"], "2.1.0");
        assert!(result.as_value()["runs"].is_array());
    }

    #[test]
    fn test_read_sarif_from_str_invalid_json() {
        let reader = JsonSarifReader;
        assert!(reader.read_sarif_from_str("not valid json").is_err());
    }

    #[test]
    fn test_read_sarif_from_str_empty_string() {
        let reader = JsonSarifReader;
        assert!(reader.read_sarif_from_str("").is_err());
    }

    #[test]
    fn test_read_sarif_from_file_valid() {
        let reader = JsonSarifReader;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, r#"{{"version":"2.1.0","runs":[]}}"#).unwrap();
        let result = reader.read_sarif_from_file(tmp.path()).unwrap();
        assert_eq!(result.as_value()["version"], "2.1.0");
    }

    #[test]
    fn test_read_sarif_from_nonexistent_file() {
        let reader = JsonSarifReader;
        let result = reader.read_sarif_from_file(Path::new("/nonexistent/__sarif_test__.sarif"));
        assert!(result.is_err());
    }

    #[test]
    fn test_sarif_schema210_round_trip() {
        let reader = JsonSarifReader;
        let json = r#"{"version":"2.1.0","$schema":"https://example.com/sarif-schema","runs":[]}"#;
        let schema = reader.read_sarif_from_str(json).unwrap();
        let inner = schema.into_inner();
        assert_eq!(inner["version"], "2.1.0");
    }
}
