use crate::sarif::SarifSchema210;
use anyhow::Result;
use std::path::Path;

use super::SarifIo;

/// SARIF JSON reader using serde_json (analogous to Java's Gson-based SarifGsonIO).
/// Parses SARIF 2.1.0 documents from files or strings.
#[derive(Debug)]
pub struct SarifGsonIO;

impl SarifIo for SarifGsonIO {
    fn read_sarif_from_file(&self, path: &Path) -> Result<SarifSchema210> {
        let content = std::fs::read_to_string(path)?;
        self.read_sarif_from_str(&content)
    }

    fn read_sarif_from_str(&self, s: &str) -> Result<SarifSchema210> {
        let value: serde_json::Value = serde_json::from_str(s)?;
        Ok(SarifSchema210::new(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_read_sarif_from_str_valid() {
        let reader = SarifGsonIO;
        let json = r#"{"version":"2.1.0","runs":[]}"#;
        let result = reader.read_sarif_from_str(json).unwrap();
        assert_eq!(result.as_value()["version"], "2.1.0");
        assert!(result.as_value()["runs"].is_array());
    }

    #[test]
    fn test_read_sarif_from_str_invalid_json() {
        let reader = SarifGsonIO;
        assert!(reader.read_sarif_from_str("not valid json").is_err());
    }

    #[test]
    fn test_read_sarif_from_str_empty_string() {
        let reader = SarifGsonIO;
        assert!(reader.read_sarif_from_str("").is_err());
    }

    #[test]
    fn test_read_sarif_from_file_valid() {
        let reader = SarifGsonIO;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, r#"{{"version":"2.1.0","runs":[]}}"#).unwrap();
        let result = reader.read_sarif_from_file(tmp.path()).unwrap();
        assert_eq!(result.as_value()["version"], "2.1.0");
    }

    #[test]
    fn test_read_sarif_from_nonexistent_file() {
        let reader = SarifGsonIO;
        let result = reader.read_sarif_from_file(Path::new("/nonexistent/__sarif_gson_io_test__.sarif"));
        assert!(result.is_err());
    }

    #[test]
    fn test_sarif_gson_io_round_trip() {
        let reader = SarifGsonIO;
        let json = r#"{"version":"2.1.0","$schema":"https://example.com/sarif-schema","runs":[]}"#;
        let schema = reader.read_sarif_from_str(json).unwrap();
        let inner = schema.into_inner();
        assert_eq!(inner["version"], "2.1.0");
    }

    #[test]
    fn test_sarif_gson_io_complex_document() {
        let reader = SarifGsonIO;
        let json = r#"
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "TestTool",
                            "version": "1.0"
                        }
                    },
                    "results": []
                }
            ]
        }
        "#;
        let result = reader.read_sarif_from_str(json).unwrap();
        assert_eq!(result.as_value()["version"], "2.1.0");
        assert_eq!(result.as_value()["runs"][0]["tool"]["driver"]["name"], "TestTool");
    }
}
