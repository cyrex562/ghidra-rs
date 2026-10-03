//! Port of `sarif.handlers.result.SarifLevelResultHandler`.

use serde_json::Value;

use crate::sarif::handlers::{SarifResultHandler, SarifResultHandlerBase};
use crate::util::classfinder::extension_point::ExtensionPoint;

/// Port of `sarif.handlers.result.SarifLevelResultHandler`.
#[derive(Default)]
pub struct SarifLevelResultHandler {
    base: SarifResultHandlerBase,
}

impl SarifLevelResultHandler {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ExtensionPoint for SarifLevelResultHandler {}

impl SarifResultHandler for SarifLevelResultHandler {
    fn base(&self) -> &SarifResultHandlerBase {
        &self.base
    }

    fn get_key(&self) -> String {
        "Level".to_string()
    }

    /// `SarifLevelResultHandler.parse()`: `result.getLevel().toString()`, or the literal
    /// `"none"` if the result has no `level` -- Java's `parse()` never returns `null`.
    fn parse(&self) -> Option<Value> {
        let result = self.base().result()?;
        let level = result.get("level").and_then(Value::as_str).unwrap_or("none");
        Some(Value::String(level.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sarif::model::SarifDataFrame;
    use crate::sarif::seam_stubs::{ProgramSarifMgr, SarifController};
    use crate::sarif::SarifSchema210;
    use serde_json::json;
    use std::collections::HashMap;

    fn make_data_frame() -> SarifDataFrame {
        let log = SarifSchema210::new(json!({ "runs": [] }));
        let controller = SarifController::new(Vec::new(), Vec::new(), ProgramSarifMgr::new("/tmp"));
        SarifDataFrame::new(&log, controller, false)
    }

    #[test]
    fn parse_returns_level_when_present() {
        let handler = SarifLevelResultHandler::new();
        let df = make_data_frame();
        let run = json!({});
        let result = json!({ "level": "warning" });
        let mut map = HashMap::new();

        handler.handle(&df, &run, &result, &mut map);

        assert_eq!(map.get("Level"), Some(&Value::String("warning".to_string())));
    }

    #[test]
    fn parse_defaults_to_none_literal_when_level_missing() {
        let handler = SarifLevelResultHandler::new();
        let df = make_data_frame();
        let run = json!({});
        let result = json!({});
        let mut map = HashMap::new();

        handler.handle(&df, &run, &result, &mut map);

        assert_eq!(map.get("Level"), Some(&Value::String("none".to_string())));
    }
}
