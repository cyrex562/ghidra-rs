//! Port of `sarif.handlers.result.SarifToolResultHandler`.

use serde_json::Value;

use crate::sarif::handlers::{SarifResultHandler, SarifResultHandlerBase};
use crate::util::classfinder::extension_point::ExtensionPoint;

/// Port of `sarif.handlers.result.SarifToolResultHandler`.
#[derive(Default)]
pub struct SarifToolResultHandler {
    base: SarifResultHandlerBase,
}

impl SarifToolResultHandler {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ExtensionPoint for SarifToolResultHandler {}

impl SarifResultHandler for SarifToolResultHandler {
    fn base(&self) -> &SarifResultHandlerBase {
        &self.base
    }

    fn get_key(&self) -> String {
        "Tool".to_string()
    }

    /// `SarifToolResultHandler.parse()`: `run.getTool().getDriver().getName()`. Java performs no
    /// null checks at all here -- a run missing `tool`/`driver`/`name` throws an uncaught
    /// `NullPointerException`, aborting the whole SARIF population. Rather than reproduce a
    /// crash, this returns `None` for a malformed run, which simply omits the `"Tool"` key from
    /// that row instead of aborting.
    fn parse(&self) -> Option<Value> {
        let run = self.base().run()?;
        let name = run.get("tool")?.get("driver")?.get("name")?.as_str()?;
        Some(Value::String(name.to_string()))
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
    fn parse_returns_driver_name() {
        let handler = SarifToolResultHandler::new();
        let df = make_data_frame();
        let run = json!({ "tool": { "driver": { "name": "Ghidra" } } });
        let result = json!({});
        let mut map = HashMap::new();

        handler.handle(&df, &run, &result, &mut map);

        assert_eq!(map.get("Tool"), Some(&Value::String("Ghidra".to_string())));
    }

    #[test]
    fn parse_returns_none_instead_of_panicking_on_malformed_run() {
        let handler = SarifToolResultHandler::new();
        let df = make_data_frame();
        let run = json!({});
        let result = json!({});
        let mut map = HashMap::new();

        handler.handle(&df, &run, &result, &mut map);

        assert!(map.get("Tool").is_none());
    }
}
