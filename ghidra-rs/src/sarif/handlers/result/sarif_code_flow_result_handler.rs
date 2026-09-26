//! Port of `sarif.handlers.result.SarifCodeFlowResultHandler`.

use serde_json::Value;

use crate::sarif::handlers::{SarifResultHandler, SarifResultHandlerBase};
use crate::util::classfinder::extension_point::ExtensionPoint;

/// Port of `sarif.handlers.result.SarifCodeFlowResultHandler`.
#[derive(Default)]
pub struct SarifCodeFlowResultHandler {
    base: SarifResultHandlerBase,
}

impl SarifCodeFlowResultHandler {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ExtensionPoint for SarifCodeFlowResultHandler {}

impl SarifResultHandler for SarifCodeFlowResultHandler {
    fn base(&self) -> &SarifResultHandlerBase {
        &self.base
    }

    fn get_key(&self) -> String {
        "CodeFlows".to_string()
    }

    /// `SarifCodeFlowResultHandler.parse()`: a `List<List<Address>>`, one inner list per thread
    /// flow, unconditionally returned (even empty) the way Java's `res` is never `null`.
    /// `parseCodeFlow`'s inner loop calls `controller.locationToAddress(...)` and adds the result
    /// unconditionally -- including `null` when a location doesn't resolve -- so a JSON `null`
    /// entry is likewise pushed here rather than being filtered out.
    fn parse(&self) -> Option<Value> {
        let controller = self.base().controller()?;
        let run = self.base().run()?;
        let result = self.base().result()?;

        let mut flows: Vec<Value> = Vec::new();
        if let Some(code_flows) = result.get("codeFlows").and_then(Value::as_array) {
            for flow in code_flows {
                let Some(thread_flows) = flow.get("threadFlows").and_then(Value::as_array) else {
                    continue;
                };
                for thread_flow in thread_flows {
                    let mut addrs: Vec<Value> = Vec::new();
                    if let Some(locations) = thread_flow.get("locations").and_then(Value::as_array) {
                        for loc_entry in locations {
                            let addr_value = loc_entry
                                .get("location")
                                .and_then(|location| controller.location_to_address(&run, location))
                                .map(|addr| Value::String(addr.to_string()))
                                .unwrap_or(Value::Null);
                            addrs.push(addr_value);
                        }
                    }
                    flows.push(Value::Array(addrs));
                }
            }
        }
        Some(Value::Array(flows))
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
    fn parse_collects_one_address_list_per_thread_flow() {
        let handler = SarifCodeFlowResultHandler::new();
        let df = make_data_frame();
        let run = json!({});
        let result = json!({
            "codeFlows": [{
                "threadFlows": [{
                    "locations": [
                        { "location": { "physicalLocation": { "address": { "absoluteAddress": 0x10 } } } },
                        { "location": { "physicalLocation": { "address": { "absoluteAddress": 0x20 } } } },
                    ]
                }]
            }]
        });
        let mut map = HashMap::new();

        handler.handle(&df, &run, &result, &mut map);

        assert_eq!(
            map.get("CodeFlows"),
            Some(&json!([["ram:0x10", "ram:0x20"]]))
        );
    }

    #[test]
    fn parse_pushes_null_for_unresolvable_location() {
        let handler = SarifCodeFlowResultHandler::new();
        let df = make_data_frame();
        let run = json!({});
        let result = json!({
            "codeFlows": [{
                "threadFlows": [{
                    "locations": [
                        { "location": { "physicalLocation": { "address": { "fullyQualifiedName": "NO ADDRESS" } } } },
                    ]
                }]
            }]
        });
        let mut map = HashMap::new();

        handler.handle(&df, &run, &result, &mut map);

        assert_eq!(map.get("CodeFlows"), Some(&json!([[Value::Null]])));
    }

    #[test]
    fn parse_returns_empty_list_when_no_code_flows() {
        let handler = SarifCodeFlowResultHandler::new();
        let df = make_data_frame();
        let run = json!({});
        let result = json!({});
        let mut map = HashMap::new();

        handler.handle(&df, &run, &result, &mut map);

        // Unlike most handlers, "CodeFlows" is always inserted -- even as an empty list.
        assert_eq!(map.get("CodeFlows"), Some(&json!([])));
    }
}
