//! Port of `sarif.handlers.SarifResultHandler`.
//!
//! Java's `SarifResultHandler` is an abstract class: it carries seven instance fields
//! (`headers`, `df`, `controller`, `run`, `result`, `provider`, `isEnabled`) and implements every
//! method except the two abstract ones (`getKey`, `parse`). Rust has no field inheritance, so
//! [`SarifResultHandlerBase`] holds the shared state, while [`SarifResultHandler`] declares the
//! abstract methods plus the concrete ones (`handle`, `getActionName`, `getProperty`, `getTask`,
//! `createAction`) as defaults that reach the state through
//! [`base`](SarifResultHandler::base) -- the same split [`AbstractStmt`](crate::pcode::r#struct::abstract_stmt::AbstractStmt)
//! uses.
//!
//! [`crate::sarif::seam_stubs::SarifController`] stores handler instances behind
//! `Arc<dyn SarifResultHandler>` (Java resolves a *set* of these at runtime via `ClassSearcher`),
//! so the mutable fields live behind `Mutex`es rather than requiring `&mut self` -- mirroring how
//! [`AbstractStmtBase`](crate::pcode::r#struct::abstract_stmt::AbstractStmtBase) guards its own
//! `parent` field for the same `Arc<dyn T>`-sharing reason.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::Value;

use crate::sarif::model::SarifDataFrame;
use crate::sarif::seam_stubs::{
    DockingAction, ProgramTask, SarifController, SarifResultsTableProvider, SimpleMenuData,
    TaskLauncher,
};
use crate::util::classfinder::extension_point::ExtensionPoint;

/// Shared state of a [`SarifResultHandler`] implementation.
///
/// Port of the seven instance fields of `sarif.handlers.SarifResultHandler`.
#[derive(Default)]
pub struct SarifResultHandlerBase {
    headers: Mutex<Vec<String>>,
    df: Mutex<Option<SarifDataFrame>>,
    controller: Mutex<Option<SarifController>>,
    run: Mutex<Option<Value>>,
    result: Mutex<Option<Value>>,
    provider: Mutex<Option<Arc<SarifResultsTableProvider>>>,
    is_enabled: Mutex<bool>,
}

impl SarifResultHandlerBase {
    /// Constructs empty state, matching `headers = new ArrayList<>()` and the rest of Java's
    /// fields defaulting to `null`/`false`.
    pub fn new() -> Self {
        Self::default()
    }

    /// `SarifResultHandler.headers`, exposed as a snapshot copy for inspection (e.g. by tests or
    /// future subclasses that build header lists).
    pub fn headers(&self) -> Vec<String> {
        self.headers.lock().unwrap().clone()
    }

    /// Appends to `SarifResultHandler.headers`, mirroring a subclass's own `headers.add(...)`.
    pub fn add_header(&self, header: impl Into<String>) {
        self.headers.lock().unwrap().push(header.into());
    }

    /// `SarifResultHandler.provider`, set by
    /// [`SarifResultHandler::create_action`].
    pub fn provider(&self) -> Option<Arc<SarifResultsTableProvider>> {
        self.provider.lock().unwrap().clone()
    }

    /// `SarifResultHandler.isEnabled`, set by [`SarifResultHandler::create_action`].
    pub fn is_enabled_flag(&self) -> bool {
        *self.is_enabled.lock().unwrap()
    }
}

/// The abstract part of `sarif.handlers.SarifResultHandler`: the two methods every concrete
/// handler must supply (`getKey`, `parse`), plus the concrete/overridable ones Java implements on
/// the base class itself.
pub trait SarifResultHandler: ExtensionPoint + Send + Sync + 'static {
    /// Access the shared handler state.
    fn base(&self) -> &SarifResultHandlerBase;

    /// `SarifResultHandler.getKey()`.
    fn get_key(&self) -> String;

    /// `SarifResultHandler.parse()`, reading through [`Self::base`]'s `df`/`controller`/`run`/
    /// `result` (set by the preceding [`Self::handle`] call) the way a Java override reads the
    /// inherited protected fields.
    fn parse(&self) -> Option<Value>;

    /// `SarifResultHandler.isEnabled(SarifDataFrame)`. Default: always enabled.
    fn is_enabled(&self, _dframe: &SarifDataFrame) -> bool {
        true
    }

    /// `SarifResultHandler.handle(SarifDataFrame, Run, Result, Map<String, Object>)`. `run` and
    /// `result` are the raw SARIF JSON objects (matching the crate's existing convention of
    /// treating SARIF payloads as [`serde_json::Value`] rather than typed
    /// `com.contrastsecurity.sarif` classes -- see [`crate::sarif::SarifSchema210`]); `map` is the
    /// row being built, matching a `Map<String, Object>` deserialized from JSON.
    fn handle(
        &self,
        dframe: &SarifDataFrame,
        run: &Value,
        result: &Value,
        map: &mut HashMap<String, Value>,
    ) {
        *self.base().df.lock().unwrap() = Some(dframe.clone());
        *self.base().controller.lock().unwrap() = Some(dframe.get_controller().clone());
        *self.base().run.lock().unwrap() = Some(run.clone());
        *self.base().result.lock().unwrap() = Some(result.clone());
        if let Some(res) = self.parse() {
            map.insert(self.get_key(), res);
        }
    }

    /// `SarifResultHandler.getActionName()`. Default: no action.
    fn get_action_name(&self) -> Option<String> {
        None
    }

    /// `SarifResultHandler.getProperty(String)`. Reads through the `result` JSON object's
    /// `"properties"` field (mirroring `PropertyBag.getAdditionalProperties()`, which this crate
    /// represents as inlined JSON keys rather than a typed `PropertyBag` -- see
    /// [`crate::sarif::SarifSchema210`]).
    fn get_property(&self, key: &str) -> Option<Value> {
        let result = self.base().result.lock().unwrap();
        result.as_ref()?.get("properties")?.get(key).cloned()
    }

    /// `SarifResultHandler.getTask(SarifResultsTableProvider)`. Default: no task.
    fn get_task(&self, _table_provider: &SarifResultsTableProvider) -> Option<Box<dyn ProgramTask>> {
        None
    }

    /// `SarifResultHandler.createAction(SarifResultsTableProvider)`. Builds the right-click
    /// action Java constructs as an anonymous `DockingAction` subclass overriding
    /// `actionPerformed`/`isEnabledForContext`/`isAddToPopup`; those three overrides become the
    /// closures [`crate::sarif::seam_stubs::DockingAction::new`] takes. `self: Arc<Self>` (rather
    /// than `&self`) is needed so the closures can hold their own handle back to the handler --
    /// the same reason `Arc<Self>`-taking builder methods appear elsewhere in this crate (see
    /// [`AbstractDomainObjectListenerBuilder::build`](crate::framework::model::AbstractDomainObjectListenerBuilder::build)
    /// for the analogous `Box<Self>` pattern).
    fn create_action(self: Arc<Self>, table_provider: Arc<SarifResultsTableProvider>) -> DockingAction {
        *self.base().provider.lock().unwrap() = Some(Arc::clone(&table_provider));
        let enabled = self.is_enabled(table_provider.get_data_frame());
        *self.base().is_enabled.lock().unwrap() = enabled;

        let action_name = self.get_action_name();
        let owner = self.get_key();

        let for_perform = Arc::clone(&self);
        let provider_for_perform = Arc::clone(&table_provider);
        let for_enabled = Arc::clone(&self);
        let for_popup = Arc::clone(&self);

        let mut action = DockingAction::new(
            action_name.clone(),
            Some(owner),
            move |_context| {
                if let Some(task) = for_perform.get_task(&provider_for_perform) {
                    TaskLauncher::launch_program_task(task.as_ref());
                }
            },
            move |_context| *for_enabled.base().is_enabled.lock().unwrap(),
            move |_context| *for_popup.base().is_enabled.lock().unwrap(),
        );
        action.set_popup_menu_data(Box::new(SimpleMenuData::new(vec![
            action_name.unwrap_or_default(),
        ])));
        action
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sarif::seam_stubs::ProgramSarifMgr;
    use crate::sarif::SarifSchema210;
    use crate::util::task::TaskMonitor;
    use serde_json::json;

    fn make_data_frame() -> SarifDataFrame {
        let log = SarifSchema210::new(json!({ "runs": [] }));
        let controller =
            SarifController::new(Vec::new(), Vec::new(), ProgramSarifMgr::new("/tmp"));
        SarifDataFrame::new(&log, controller, false)
    }

    struct CommentHandler {
        base: SarifResultHandlerBase,
    }

    impl CommentHandler {
        fn new() -> Self {
            Self { base: SarifResultHandlerBase::new() }
        }
    }

    impl ExtensionPoint for CommentHandler {}

    impl SarifResultHandler for CommentHandler {
        fn base(&self) -> &SarifResultHandlerBase {
            &self.base
        }

        fn get_key(&self) -> String {
            "Comment".to_string()
        }

        fn parse(&self) -> Option<Value> {
            self.get_property("msg")
        }
    }

    struct NeverMatchesHandler {
        base: SarifResultHandlerBase,
    }

    impl ExtensionPoint for NeverMatchesHandler {}

    impl SarifResultHandler for NeverMatchesHandler {
        fn base(&self) -> &SarifResultHandlerBase {
            &self.base
        }

        fn get_key(&self) -> String {
            "NeverMatches".to_string()
        }

        fn parse(&self) -> Option<Value> {
            None
        }
    }

    #[test]
    fn handle_inserts_parsed_value_under_key() {
        let handler = CommentHandler::new();
        let df = make_data_frame();
        let run = json!({});
        let result = json!({ "properties": { "msg": "hello" } });
        let mut map = HashMap::new();

        handler.handle(&df, &run, &result, &mut map);

        assert_eq!(map.get("Comment"), Some(&json!("hello")));
    }

    #[test]
    fn handle_skips_map_insert_when_parse_returns_none() {
        let handler = NeverMatchesHandler {
            base: SarifResultHandlerBase::new(),
        };
        let df = make_data_frame();
        let run = json!({});
        let result = json!({ "properties": { "msg": "hello" } });
        let mut map = HashMap::new();

        handler.handle(&df, &run, &result, &mut map);

        assert!(map.is_empty());
    }

    #[test]
    fn get_property_missing_properties_returns_none() {
        let handler = CommentHandler::new();
        let df = make_data_frame();
        let run = json!({});
        let result = json!({});
        let mut map = HashMap::new();

        handler.handle(&df, &run, &result, &mut map);

        assert!(map.get("Comment").is_none());
    }

    #[test]
    fn default_is_enabled_is_true() {
        let handler = CommentHandler::new();
        let df = make_data_frame();
        assert!(handler.is_enabled(&df));
    }

    struct RecordingTask {
        ran: Arc<Mutex<bool>>,
    }

    impl ProgramTask for RecordingTask {
        fn run(&self, _monitor: &dyn TaskMonitor) {
            *self.ran.lock().unwrap() = true;
        }
    }

    struct ConditionalHandler {
        base: SarifResultHandlerBase,
        ran: Arc<Mutex<bool>>,
    }

    impl ExtensionPoint for ConditionalHandler {}

    impl SarifResultHandler for ConditionalHandler {
        fn base(&self) -> &SarifResultHandlerBase {
            &self.base
        }

        fn get_key(&self) -> String {
            "Conditional".to_string()
        }

        fn parse(&self) -> Option<Value> {
            None
        }

        fn is_enabled(&self, _dframe: &SarifDataFrame) -> bool {
            false
        }

        fn get_task(
            &self,
            _table_provider: &SarifResultsTableProvider,
        ) -> Option<Box<dyn ProgramTask>> {
            Some(Box::new(RecordingTask { ran: Arc::clone(&self.ran) }))
        }
    }

    #[derive(Default)]
    struct MockActionContext;

    impl crate::docking::action_context::ActionContext for MockActionContext {
        fn component_provider(
            &self,
        ) -> Option<Arc<dyn crate::docking::seam_stubs::ComponentProvider>> {
            None
        }
        fn context_object(&self) -> Option<Arc<dyn std::any::Any + Send + Sync>> {
            None
        }
        fn set_context_object(&mut self, _context_object: Option<Arc<dyn std::any::Any + Send + Sync>>) {}
        fn set_event_click_modifiers(&mut self, _modifiers: i32) {}
        fn event_click_modifiers(&self) -> i32 {
            0
        }
        fn has_any_event_click_modifiers(&self, _modifiers_mask: i32) -> bool {
            false
        }
        fn set_source_object(&mut self, _source_object: Option<Arc<dyn std::any::Any + Send + Sync>>) {}
        fn source_object(&self) -> Option<Arc<dyn std::any::Any + Send + Sync>> {
            None
        }
        fn set_context_provider(
            &mut self,
            _provider: Option<Arc<dyn crate::docking::seam_stubs::ActionContextProvider>>,
        ) {
        }
        fn context_provider(&self) -> Option<Arc<dyn crate::docking::seam_stubs::ActionContextProvider>> {
            None
        }
        fn set_mouse_event(&mut self, _event: Option<Arc<dyn crate::docking::seam_stubs::MouseEvent>>) {}
        fn mouse_event(&self) -> Option<Arc<dyn crate::docking::seam_stubs::MouseEvent>> {
            None
        }
        fn source_component(&self) -> Option<Arc<dyn crate::docking::seam_stubs::Component>> {
            None
        }
        fn set_source_component(&mut self, _component: Option<Arc<dyn crate::docking::seam_stubs::Component>>) {}
    }

    #[test]
    fn create_action_reflects_is_enabled_and_launches_task() {
        let ran = Arc::new(Mutex::new(false));
        let handler = Arc::new(ConditionalHandler {
            base: SarifResultHandlerBase::new(),
            ran: Arc::clone(&ran),
        });
        let df = make_data_frame();
        let controller = SarifController::new(Vec::new(), Vec::new(), ProgramSarifMgr::new("/tmp"));
        let table_provider = Arc::new(SarifResultsTableProvider::new(controller, df));

        let action = Arc::clone(&handler).create_action(Arc::clone(&table_provider));
        let ctx = MockActionContext;

        assert!(!action.is_enabled_for_context(&ctx));
        assert!(!action.is_add_to_popup(&ctx));
        assert!(!*ran.lock().unwrap());

        action.action_performed(&ctx);
        assert!(*ran.lock().unwrap());
        assert_eq!(handler.base().is_enabled_flag(), false);
        assert!(handler.base().provider().is_some());
    }
}
