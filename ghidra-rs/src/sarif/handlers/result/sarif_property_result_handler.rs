//! Port of `sarif.handlers.result.SarifPropertyResultHandler`.

use std::collections::HashMap;

use serde_json::Value;

use crate::sarif::handlers::{SarifResultHandler, SarifResultHandlerBase};
use crate::sarif::model::SarifDataFrame;
use crate::util::classfinder::extension_point::ExtensionPoint;

/// Promotes SARIF result properties keyed `"viewer/table/<column>"` into their own table
/// columns, and forwards properties keyed `"listing/<action>"` to
/// [`SarifController::handle_listing_action`](crate::sarif::seam_stubs::SarifController::handle_listing_action).
///
/// Port of `sarif.handlers.result.SarifPropertyResultHandler`. Unlike every other handler in
/// this package, [`Self::handle`] is fully overridden rather than delegating to
/// [`SarifResultHandler::handle`]'s default -- and, faithfully to Java, that override only ever
/// assigns the inherited `controller` field, never `df`/`run`/`result`. Those three stay `None`
/// in [`Self::base`] forever, so [`Self::parse`] (declared only to satisfy the trait -- Java's
/// override never calls it either) can never do useful work. In Java this is silent because
/// `parse()` is simply dead code reachable only via direct reflection/testing; a hypothetical
/// direct call there would NPE (`run`/`result` are null), whereas here it just returns `None`.
///
/// Java also wraps the property loop in `Program.openTransaction(...)`; since no `Program` is
/// wired into this seam (see [`crate::sarif::seam_stubs::SarifController`]'s own doc comment),
/// that transaction wrapper is omitted here -- there is nothing transactional left to wrap.
#[derive(Default)]
pub struct SarifPropertyResultHandler {
    base: SarifResultHandlerBase,
}

impl SarifPropertyResultHandler {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ExtensionPoint for SarifPropertyResultHandler {}

impl SarifResultHandler for SarifPropertyResultHandler {
    fn base(&self) -> &SarifResultHandlerBase {
        &self.base
    }

    fn get_key(&self) -> String {
        "Property".to_string()
    }

    /// `SarifPropertyResultHandler.parse()`. Dead in practice -- see the struct doc.
    fn parse(&self) -> Option<Value> {
        let controller = self.base().controller()?;
        let run = self.base().run()?;
        let result = self.base().result()?;
        let addrs: Vec<Value> = controller
            .get_listing_addresses(&run, &result)
            .into_iter()
            .map(|addr| Value::String(addr.to_string()))
            .collect();
        Some(Value::Array(addrs))
    }

    /// `SarifPropertyResultHandler.handle(SarifDataFrame, Run, Result, Map<String, Object>)`.
    fn handle(
        &self,
        dframe: &SarifDataFrame,
        run: &Value,
        result: &Value,
        map: &mut HashMap<String, Value>,
    ) {
        let controller = dframe.get_controller().clone();
        self.base().set_controller(controller.clone());

        let Some(properties) = result.get("properties") else {
            return;
        };
        let Some(additional) = properties.as_object() else {
            return;
        };

        for (key, value) in additional {
            // Java: `String[] splits = key.split("/");` -- unbounded, so `splits[N]` indexes the
            // Nth `/`-separated segment regardless of how many trailing segments follow.
            let splits: Vec<&str> = key.split('/').collect();
            match splits.first().copied() {
                Some("viewer") => {
                    // Java's inner `switch (splits[1])` throws `ArrayIndexOutOfBoundsException`
                    // for a key with no second segment (e.g. bare `"viewer"`), aborting the
                    // whole population. We skip that malformed entry instead of panicking.
                    if splits.get(1) == Some(&"table") {
                        if let Some(&column) = splits.get(2) {
                            dframe.add_dynamic_column_if_absent(column, false);
                            map.insert(column.to_string(), value.clone());
                        }
                    }
                }
                Some("listing") => {
                    // Java: `splits[1]` -- same AIOOBE-on-malformed-key caveat as above.
                    if let Some(&action) = splits.get(1) {
                        controller.handle_listing_action(run, result, action, value);
                    }
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sarif::seam_stubs::{ProgramSarifMgr, SarifController};
    use crate::sarif::SarifSchema210;
    use serde_json::json;

    fn make_data_frame() -> (SarifDataFrame, SarifController) {
        let controller = SarifController::new(Vec::new(), Vec::new(), ProgramSarifMgr::new("/tmp"));
        let log = SarifSchema210::new(json!({ "runs": [] }));
        let df = SarifDataFrame::new(&log, controller.clone(), false);
        (df, controller)
    }

    #[test]
    fn viewer_table_property_adds_dynamic_column_and_map_entry() {
        let handler = SarifPropertyResultHandler::new();
        let (df, _controller) = make_data_frame();
        let run = json!({});
        let result = json!({
            "properties": { "viewer/table/MyColumn": "hello" }
        });
        let mut map = HashMap::new();

        handler.handle(&df, &run, &result, &mut map);

        assert_eq!(map.get("MyColumn"), Some(&Value::String("hello".to_string())));
        let dynamic = df.dynamic_columns();
        assert_eq!(dynamic.len(), 1);
        assert_eq!(dynamic[0].name(), "MyColumn");
        assert!(!dynamic[0].is_hidden());
    }

    #[test]
    fn existing_column_is_not_duplicated() {
        let handler = SarifPropertyResultHandler::new();
        let (df, _controller) = make_data_frame();
        let run = json!({});
        // "Address" is one of the six fixed columns SarifDataFrame::new always seeds.
        let result = json!({
            "properties": { "viewer/table/Address": "0xdeadbeef" }
        });
        let mut map = HashMap::new();

        handler.handle(&df, &run, &result, &mut map);

        assert!(map.contains_key("Address"));
        assert!(df.dynamic_columns().is_empty());
    }

    #[test]
    fn listing_property_forwards_to_controller_handle_listing_action() {
        let handler = SarifPropertyResultHandler::new();
        let (df, controller) = make_data_frame();
        let run = json!({});
        let result = json!({
            "locations": [{ "physicalLocation": { "address": { "absoluteAddress": 0x100 } } }],
            "properties": { "listing/comment": "a note" }
        });
        let mut map = HashMap::new();

        handler.handle(&df, &run, &result, &mut map);

        let recorded = controller.listing_actions();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].key, "comment");
        assert_eq!(recorded[0].value, Value::String("a note".to_string()));
        assert_eq!(recorded[0].address.to_string(), "ram:0x100");
    }

    #[test]
    fn handle_returns_early_when_no_properties() {
        let handler = SarifPropertyResultHandler::new();
        let (df, _controller) = make_data_frame();
        let run = json!({});
        let result = json!({});
        let mut map = HashMap::new();

        handler.handle(&df, &run, &result, &mut map);

        assert!(map.is_empty());
    }

    #[test]
    fn handle_sets_only_controller_never_df_run_result() {
        // Faithful to Java: the overridden handle() assigns `this.controller` but never touches
        // the `df`/`run`/`result` fields the base class's own handle() would have set.
        let handler = SarifPropertyResultHandler::new();
        let (df, _controller) = make_data_frame();
        let run = json!({});
        let result = json!({ "properties": { "viewer/table/X": 1 } });
        let mut map = HashMap::new();

        handler.handle(&df, &run, &result, &mut map);

        assert!(handler.base().controller().is_some());
        assert!(handler.base().run().is_none());
        assert!(handler.base().result().is_none());
        assert!(handler.base().df().is_none());
        // parse() is consequently unreachable-in-practice dead code: it returns None here.
        assert_eq!(handler.parse(), None);
    }

    #[test]
    fn malformed_viewer_key_with_no_second_segment_is_skipped_not_panicked() {
        let handler = SarifPropertyResultHandler::new();
        let (df, _controller) = make_data_frame();
        let run = json!({});
        let result = json!({ "properties": { "viewer": "oops" } });
        let mut map = HashMap::new();

        handler.handle(&df, &run, &result, &mut map);

        assert!(map.is_empty());
    }
}
