//! Port of `sarif.handlers.result.SarifRuleIdResultHandler`.

use serde_json::Value;

use crate::sarif::handlers::{SarifResultHandler, SarifResultHandlerBase};
use crate::util::classfinder::extension_point::ExtensionPoint;

/// Port of `sarif.handlers.result.SarifRuleIdResultHandler`.
#[derive(Default)]
pub struct SarifRuleIdResultHandler {
    base: SarifResultHandlerBase,
}

impl SarifRuleIdResultHandler {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ExtensionPoint for SarifRuleIdResultHandler {}

impl SarifResultHandler for SarifRuleIdResultHandler {
    fn base(&self) -> &SarifResultHandlerBase {
        &self.base
    }

    fn get_key(&self) -> String {
        "RuleId".to_string()
    }

    /// `SarifRuleIdResultHandler.parse()`: `result.getRuleId()`, which may be `null`.
    fn parse(&self) -> Option<Value> {
        let result = self.base().result()?;
        result
            .get("ruleId")
            .and_then(Value::as_str)
            .map(|s| Value::String(s.to_string()))
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
    fn parse_returns_rule_id_when_present() {
        let handler = SarifRuleIdResultHandler::new();
        let df = make_data_frame();
        let run = json!({});
        let result = json!({ "ruleId": "R1001" });
        let mut map = HashMap::new();

        handler.handle(&df, &run, &result, &mut map);

        assert_eq!(map.get("RuleId"), Some(&Value::String("R1001".to_string())));
    }

    #[test]
    fn parse_returns_none_when_rule_id_missing() {
        let handler = SarifRuleIdResultHandler::new();
        let df = make_data_frame();
        let run = json!({});
        let result = json!({});
        let mut map = HashMap::new();

        handler.handle(&df, &run, &result, &mut map);

        assert!(map.get("RuleId").is_none());
    }
}
