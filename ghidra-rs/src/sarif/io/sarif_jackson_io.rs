use crate::sarif::SarifSchema210;
use anyhow::{anyhow, Result};
use std::path::Path;

use super::SarifIo;

/// SARIF reader using Jackson (Java library).
/// This implementation is not currently supported in Rust.
/// Mirrors the Java class `sarif.io.SarifJacksonIO`.
#[derive(Debug)]
pub struct SarifJacksonIO;

impl SarifIo for SarifJacksonIO {
    fn read_sarif_from_file(&self, _path: &Path) -> Result<SarifSchema210> {
        Err(anyhow!("Jackson not currently supported"))
    }

    fn read_sarif_from_str(&self, _s: &str) -> Result<SarifSchema210> {
        Err(anyhow!("Jackson not currently supported"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_jackson_io_read_from_file_not_supported() {
        let reader = SarifJacksonIO;
        let result = reader.read_sarif_from_file(Path::new("test.sarif"));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Jackson not currently supported"));
    }

    #[test]
    fn test_jackson_io_read_from_str_not_supported() {
        let reader = SarifJacksonIO;
        let result = reader.read_sarif_from_str("{}");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Jackson not currently supported"));
    }

    #[test]
    fn test_jackson_io_read_from_valid_json_still_not_supported() {
        let reader = SarifJacksonIO;
        let json = r#"{"version":"2.1.0","runs":[]}"#;
        let result = reader.read_sarif_from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_jackson_io_read_from_file_with_nonexistent_path_still_not_supported() {
        let reader = SarifJacksonIO;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, r#"{{"version":"2.1.0","runs":[]}}"#).unwrap();
        let result = reader.read_sarif_from_file(tmp.path());
        assert!(result.is_err());
    }
}
