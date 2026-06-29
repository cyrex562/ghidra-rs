pub mod io;
pub mod model;

use serde::{Deserialize, Serialize};

/// The root SARIF 2.1.0 schema object.
/// Mirrors `com.contrastsecurity.sarif.SarifSchema210` from the contrastsecurity library.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifSchema210(serde_json::Value);

impl SarifSchema210 {
    pub fn new(value: serde_json::Value) -> Self {
        Self(value)
    }

    pub fn into_inner(self) -> serde_json::Value {
        self.0
    }

    pub fn as_value(&self) -> &serde_json::Value {
        &self.0
    }
}
