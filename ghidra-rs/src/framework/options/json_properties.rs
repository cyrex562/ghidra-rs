//! Port of `ghidra.framework.options.JSonProperties`.

use std::io;
use std::path::Path;

use crate::framework::options::g_properties::GProperties;

/// Port of `ghidra.framework.options.JSonProperties`: a [`GProperties`] read from a file written
/// by [`GProperties::save_to_json_file`].
pub struct JSonProperties;

impl JSonProperties {
    /// `new JSonProperties(File)`.
    pub fn from_file(file: &Path) -> io::Result<GProperties> {
        let text = std::fs::read_to_string(file)?;
        let value: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        GProperties::from_json(&value).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}
