//! Port of `sarif.handlers.result.SarifKindResultHandler`.

use serde_json::Value;

use crate::sarif::handlers::{SarifResultHandler, SarifResultHandlerBase};
use crate::util::classfinder::extension_point::ExtensionPoint;

/// Port of `sarif.handlers.result.SarifKindResultHandler`.
#[derive(Default)]
pub struct SarifKindResultHandler {
    base: SarifResultHandlerBase,
}

impl SarifKindResultHandler {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ExtensionPoint for SarifKindResultHandler {}

impl SarifResultHandler for SarifKindResultHandler {
    fn base(&self) -> &SarifResultHandlerBase {
        &self.base
    }

    fn get_key(&self) -> String {
        "Kind".to_string()
    }

    /// `SarifKindResultHandler.parse()`: `result.getKind().toString()`, or the literal `"none"`
    /// if the result has no `kind` -- Java's `parse()` never returns `null`.
    fn parse(&self) -> Option<Value> {
        let result = self.base().result()?;
        let kind = result.get("kind").and_then(Value::as_str).unwrap_or("none");
        Some(Value::String(kind.to_string()))
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
    fn parse_returns_kind_when_present() {
        let handler = SarifKindResultHandler::new();
        let df = make_data_frame();
        let run = json!({});
        let result = json!({ "kind": "fail" });
        let mut map = HashMap::new();

        handler.handle(&df, &run, &result, &mut map);

        assert_eq!(map.get("Kind"), Some(&Value::String("fail".to_string())));
    }

    #[test]
    fn parse_defaults_to_none_literal_when_kind_missing() {
        let handler = SarifKindResultHandler::new();
        let df = make_data_frame();
        let run = json!({});
        let result = json!({});
        let mut map = HashMap::new();

        handler.handle(&df, &run, &result, &mut map);

        assert_eq!(map.get("Kind"), Some(&Value::String("none".to_string())));
    }
}
