//! Port of `sarif.handlers.result.SarifAddressResultHandler`.

use serde_json::Value;

use crate::sarif::handlers::{SarifResultHandler, SarifResultHandlerBase};
use crate::util::classfinder::extension_point::ExtensionPoint;

/// If we can parse a listing address, we can make the table navigate there when selected.
///
/// Port of `sarif.handlers.result.SarifAddressResultHandler`.
#[derive(Default)]
pub struct SarifAddressResultHandler {
    base: SarifResultHandlerBase,
}

impl SarifAddressResultHandler {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ExtensionPoint for SarifAddressResultHandler {}

impl SarifResultHandler for SarifAddressResultHandler {
    fn base(&self) -> &SarifResultHandlerBase {
        &self.base
    }

    fn get_key(&self) -> String {
        "Address".to_string()
    }

    /// `SarifAddressResultHandler.parse()`: the first listing address for this result, encoded
    /// as its `Display` string, or `None` (Java: `null`) if there are none.
    fn parse(&self) -> Option<Value> {
        let controller = self.base().controller()?;
        let run = self.base().run()?;
        let result = self.base().result()?;
        controller
            .get_listing_addresses(&run, &result)
            .into_iter()
            .next()
            .map(|addr| Value::String(addr.to_string()))
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
    fn parse_returns_first_resolvable_address() {
        let handler = SarifAddressResultHandler::new();
        let df = make_data_frame();
        let run = json!({});
        let result = json!({
            "locations": [
                { "physicalLocation": { "address": { "absoluteAddress": 0x1000 } } },
                { "physicalLocation": { "address": { "absoluteAddress": 0x2000 } } },
            ]
        });
        let mut map = HashMap::new();

        handler.handle(&df, &run, &result, &mut map);

        assert_eq!(map.get("Address"), Some(&Value::String("ram:0x1000".to_string())));
    }

    #[test]
    fn parse_returns_none_when_no_locations() {
        let handler = SarifAddressResultHandler::new();
        let df = make_data_frame();
        let run = json!({});
        let result = json!({});
        let mut map = HashMap::new();

        handler.handle(&df, &run, &result, &mut map);

        assert!(map.get("Address").is_none());
    }

    #[test]
    fn get_key_is_address() {
        assert_eq!(SarifAddressResultHandler::new().get_key(), "Address");
    }
}
