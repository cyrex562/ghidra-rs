//! Port of `ghidra.app.plugin.core.decompile.DecompilerActionContext`.
//!
//! The `ActionContext` produced by the Decompiler window: which function/line/token the user was
//! looking at, and whether the decompiler was still working.
//!
//! # Shape
//!
//! Java's `DecompilerActionContext` is a concrete class (nothing extends it), so it becomes a
//! plain `struct` (rule R14a-concrete-leaf). It also extends `NavigatableActionContext` (already
//! ported here as a trait mixin -- see that module) and implements the marker trait
//! `RestrictedAddressSetContext`; both are implemented directly on this struct.
//!
//! Java's `ActionContext`/`ProgramActionContext`/`ProgramLocationActionContext` ancestors --
//! which actually own the generic click-modifiers/source-object/mouse-event/etc. state this class
//! inherits -- are not ported as concrete classes; only `docking::action_context::ActionContext`
//! (the outermost interface) exists, as a trait. This struct therefore holds that generic state
//! itself, the same way the trait's own test mocks do, since there is no ancestor struct to
//! delegate to.
//!
//! Two Java methods (`hasSelection()`, `getFunctionForLocation()`) `@Override` methods declared on
//! that same unported ancestor chain. With no trait method to override, they're ported as plain
//! inherent methods carrying only the behavior this class itself adds; see their docs for what's
//! necessarily left out.

use std::any::Any;
use std::cell::OnceCell;
use std::sync::Arc;

use crate::app::context::{NavigatableActionContext, NavigationActionContext, RestrictedAddressSetContext};
use crate::app::decompiler::{ClangToken, ClangTokenGroup, ClangTokenKind};
use crate::app::seam_stubs::{DecompilerPanel, DecompilerProvider, DecompilerUtils, Navigatable};
use crate::docking::action_context::ActionContext;
use crate::docking::seam_stubs::{ActionContextProvider, Component, ComponentProvider, MouseEvent};
use crate::framework::seam_stubs::PluginTool;
use crate::program::model::address::Address;
use crate::program::model::listing::{Function, Program};
use crate::program::model::pcode::HighFunction;

/// The `ActionContext` produced by the Decompiler window.
///
/// Port of `ghidra.app.plugin.core.decompile.DecompilerActionContext`.
pub struct DecompilerActionContext {
    provider: Arc<dyn DecompilerProvider>,
    function_entry_point: Option<Address>,
    is_decompiling: bool,
    line_number: i32,

    /// Caches [`get_token_at_cursor`](Self::get_token_at_cursor)'s result after the first call.
    /// Port of the `tokenAtCursor`/`tokenIsInitialized` field pair: a `OnceCell` folds both into
    /// one field, since "initialized to `None`" and "not yet computed" are otherwise
    /// indistinguishable in Rust without a second flag.
    token_at_cursor: OnceCell<Option<Box<dyn ClangToken>>>,

    // Generic `ActionContext` state. Java holds this on the unported `ActionContext` base class;
    // see the module docs for why it lives here instead.
    context_object: Option<Arc<dyn Any + Send + Sync>>,
    source_object: Option<Arc<dyn Any + Send + Sync>>,
    click_modifiers: i32,
    context_provider: Option<Arc<dyn ActionContextProvider>>,
    mouse_event: Option<Arc<dyn MouseEvent>>,
    source_component: Option<Arc<dyn Component>>,
}

impl DecompilerActionContext {
    /// Construct a context specifying the line number.
    ///
    /// The specified line number may not necessarily correspond to that of the current token.
    /// This is usually the case when the user clicks somewhere where a token is not present, e.g.
    /// the margin. In these cases, the line number should be that under the mouse cursor.
    ///
    /// Port of `DecompilerActionContext(DecompilerProvider, Address, boolean, int)`.
    ///
    /// # Panics
    /// Panics if `line_number < 0`, mirroring the Java constructor's `IllegalArgumentException`.
    pub fn new(
        provider: Arc<dyn DecompilerProvider>,
        function_entry_point: Option<Address>,
        is_decompiling: bool,
        line_number: i32,
    ) -> Self {
        assert!(
            line_number >= 0,
            "lineNumber must be >= 0. Got {line_number}"
        );
        Self {
            provider,
            function_entry_point,
            is_decompiling,
            line_number,
            token_at_cursor: OnceCell::new(),
            context_object: None,
            source_object: None,
            click_modifiers: 0,
            context_provider: None,
            mouse_event: None,
            source_component: None,
        }
    }

    /// Construct a context using the current token's line number.
    ///
    /// Port of `DecompilerActionContext(DecompilerProvider, Address, boolean)`.
    pub fn with_current_line(
        provider: Arc<dyn DecompilerProvider>,
        function_entry_point: Option<Address>,
        is_decompiling: bool,
    ) -> Self {
        Self::new(provider, function_entry_point, is_decompiling, 0)
    }

    /// Port of `DecompilerActionContext.getFunctionEntryPoint()`.
    pub fn get_function_entry_point(&self) -> Option<&Address> {
        self.function_entry_point.as_ref()
    }

    /// Port of `DecompilerActionContext.isDecompiling()`.
    pub fn is_decompiling(&self) -> bool {
        self.is_decompiling
    }

    /// Port of `DecompilerActionContext.getComponentProvider()`, which covariantly narrows
    /// `ActionContext.getComponentProvider()`'s return type from `ComponentProvider` to
    /// `DecompilerProvider`. Rust has no covariant-return overriding, so this is a separate
    /// inherent method rather than an override of
    /// [`ActionContext::component_provider`](crate::docking::action_context::ActionContext::component_provider).
    pub fn get_component_provider(&self) -> &Arc<dyn DecompilerProvider> {
        &self.provider
    }

    /// Port of `DecompilerActionContext.getTool()`.
    pub fn get_tool(&self) -> Arc<dyn PluginTool> {
        self.get_component_provider().get_tool()
    }

    /// Port of `DecompilerActionContext.getTokenAtCursor()`.
    pub fn get_token_at_cursor(&self) -> Option<&dyn ClangToken> {
        self.token_at_cursor
            .get_or_init(|| self.get_decompiler_panel().get_token_at_cursor())
            .as_deref()
    }

    /// Get the line number.
    ///
    /// This may not always correspond to the line number of the token at the cursor. For
    /// example, if there is no token under the mouse, or if the context is produced by the
    /// margin. When generated by a mouse event, this is the line number determined by the
    /// mouse's vertical position. Otherwise, this is the line number of the current token. If
    /// there is no current token and the line number was not given at construction, this returns
    /// 0 to indicate this context has no line number.
    ///
    /// Port of `DecompilerActionContext.getLineNumber()`.
    pub fn get_line_number(&self) -> i32 {
        if self.line_number != 0 {
            return self.line_number;
        }
        self.get_token_at_cursor()
            .and_then(|token| token.get_line_parent())
            .unwrap_or(0)
    }

    /// Port of `DecompilerActionContext.getDecompilerPanel()`.
    pub fn get_decompiler_panel(&self) -> Box<dyn DecompilerPanel> {
        self.get_component_provider().get_decompiler_panel()
    }

    /// Port of `DecompilerActionContext.getFunction()`.
    pub fn get_function(&self) -> Option<Arc<dyn Function>> {
        self.get_component_provider().get_controller().get_function()
    }

    /// Port of `DecompilerActionContext.getHighFunction()`.
    pub fn get_high_function(&self) -> Option<Arc<dyn HighFunction>> {
        self.get_component_provider()
            .get_controller()
            .get_high_function()
    }

    /// Port of `DecompilerActionContext.getCCodeModel()`.
    pub fn get_c_code_model(&self) -> Option<ClangTokenGroup> {
        self.get_component_provider()
            .get_controller()
            .get_c_code_model()
    }

    /// Port of `DecompilerActionContext.hasRealFunction()`.
    ///
    /// Java also excludes `UndefinedFunction` instances via `!(f instanceof UndefinedFunction)`.
    /// [`Function`] carries no `Any`/downcast capability -- the same limitation already noted on
    /// [`UndefinedFunction::undefined_function_eq`](crate::util::undefined_function::UndefinedFunction::undefined_function_eq)
    /// for this exact class pair -- so that half of the check cannot be reproduced here; only
    /// null-ness is tested.
    pub fn has_real_function(&self) -> bool {
        self.get_function().is_some()
    }

    /// Port of `DecompilerActionContext.setStatusMessage(String)`.
    pub fn set_status_message(&self, msg: &str) {
        self.get_component_provider()
            .get_controller()
            .set_status_message(msg);
    }

    /// Port of `DecompilerActionContext.hasSelection()`, which `@Override`s a method declared on
    /// the unported `ProgramLocationActionContext` ancestor. Only the override's own added
    /// check -- the decompiler's textual selection -- is modeled; the `super.hasSelection()`
    /// fallback (a `ProgramSelection`-based check on that ancestor) isn't available here and is
    /// conservatively treated as "no selection".
    pub fn has_selection(&self) -> bool {
        let text_selection = self.provider.get_text_selection();
        !text_selection.trim().is_empty()
    }

    /// Port of `DecompilerActionContext.getFunctionForLocation()`, which `@Override`s a
    /// `protected` method declared on the unported `ProgramLocationActionContext` ancestor.
    /// Java's `token instanceof ClangFuncNameToken` dispatches on the unported `ClangFuncNameToken`
    /// subclass; [`ClangToken::kind`] stands in for that check (see the module docs on
    /// [`ClangTokenKind`]).
    pub fn get_function_for_location(&self) -> Option<Arc<dyn Function>> {
        let token = self.get_token_at_cursor()?;
        if token.kind() != ClangTokenKind::FuncName {
            return None;
        }
        let program = self.get_navigatable().get_program();
        DecompilerUtils::get_function(program.as_ref(), token)
    }
}

impl ActionContext for DecompilerActionContext {
    /// Java's `ActionContext.getComponentProvider()` returns the same `DecompilerProvider` as
    /// [`get_component_provider`](Self::get_component_provider), just typed as the base
    /// `ComponentProvider`. `docking::seam_stubs::ComponentProvider` is currently an empty marker
    /// with no real implementors, so there is nothing to adapt `provider` into yet; this returns
    /// `None` until that type is ported, matching every other `ActionContext` implementor in this
    /// crate today.
    fn component_provider(&self) -> Option<Arc<dyn ComponentProvider>> {
        None
    }

    fn context_object(&self) -> Option<Arc<dyn Any + Send + Sync>> {
        self.context_object.clone()
    }

    fn set_context_object(&mut self, context_object: Option<Arc<dyn Any + Send + Sync>>) {
        self.context_object = context_object;
    }

    fn set_event_click_modifiers(&mut self, modifiers: i32) {
        self.click_modifiers = modifiers;
    }

    fn event_click_modifiers(&self) -> i32 {
        self.click_modifiers
    }

    fn has_any_event_click_modifiers(&self, modifiers_mask: i32) -> bool {
        self.click_modifiers & modifiers_mask != 0
    }

    fn set_source_object(&mut self, source_object: Option<Arc<dyn Any + Send + Sync>>) {
        self.source_object = source_object;
    }

    fn source_object(&self) -> Option<Arc<dyn Any + Send + Sync>> {
        self.source_object.clone()
    }

    fn set_context_provider(&mut self, provider: Option<Arc<dyn ActionContextProvider>>) {
        self.context_provider = provider;
    }

    fn context_provider(&self) -> Option<Arc<dyn ActionContextProvider>> {
        self.context_provider.clone()
    }

    fn set_mouse_event(&mut self, event: Option<Arc<dyn MouseEvent>>) {
        self.mouse_event = event;
    }

    fn mouse_event(&self) -> Option<Arc<dyn MouseEvent>> {
        self.mouse_event.clone()
    }

    fn source_component(&self) -> Option<Arc<dyn Component>> {
        self.source_component.clone()
    }

    fn set_source_component(&mut self, component: Option<Arc<dyn Component>>) {
        self.source_component = component;
    }
}

impl NavigationActionContext for DecompilerActionContext {}

impl NavigatableActionContext for DecompilerActionContext {
    /// Port of `NavigatableActionContext.getNavigatable()`. Java's constructor passes the same
    /// `DecompilerProvider` as both the `ComponentProvider` and the `Navigatable` (`super(provider,
    /// provider)`); this wraps [`provider`](Self) in a thin adapter to hand back a `dyn
    /// Navigatable`, since [`DecompilerProvider`] declares `Navigatable` as a supertrait rather
    /// than being one (avoiding a dependency on trait-object upcasting).
    fn get_navigatable(&self) -> Arc<dyn Navigatable> {
        struct AsNavigatable(Arc<dyn DecompilerProvider>);

        impl Navigatable for AsNavigatable {
            fn is_connected(&self) -> bool {
                self.0.is_connected()
            }

            fn get_program(&self) -> Box<dyn Program> {
                self.0.get_program()
            }
        }

        Arc::new(AsNavigatable(self.provider.clone()))
    }
}

impl RestrictedAddressSetContext for DecompilerActionContext {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    use crate::app::decompiler::{ClangLine, ClangTokenBase};
    use crate::app::seam_stubs::DecompilerController;

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock".to_string()
        }
    }

    struct MockTool;
    impl PluginTool for MockTool {}

    struct MockController;
    impl DecompilerController for MockController {
        fn get_function(&self) -> Option<Arc<dyn Function>> {
            None
        }
        fn get_high_function(&self) -> Option<Arc<dyn HighFunction>> {
            None
        }
        fn get_c_code_model(&self) -> Option<ClangTokenGroup> {
            None
        }
        fn set_status_message(&self, _message: &str) {}
    }

    /// A [`DecompilerPanel`] whose `get_token_at_cursor` counts its calls (so tests can verify
    /// [`DecompilerActionContext::get_token_at_cursor`]'s caching) and, when `has_token` is set,
    /// hands back a token on line 7 with [`ClangTokenKind::Generic`] (i.e. not a
    /// `ClangFuncNameToken`).
    #[derive(Clone)]
    struct CountingPanel {
        calls: Arc<AtomicU32>,
        has_token: bool,
    }

    impl DecompilerPanel for CountingPanel {
        fn get_token_at_cursor(&self) -> Option<Box<dyn ClangToken>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if !self.has_token {
                return None;
            }
            let line = ClangLine::new(7, 0);
            let mut token = ClangTokenBase::with_text(None, "foo");
            token.set_line_parent(&line);
            Some(Box::new(token))
        }
    }

    struct MockProvider {
        panel: CountingPanel,
        text_selection: String,
        connected: bool,
    }

    impl Navigatable for MockProvider {
        fn is_connected(&self) -> bool {
            self.connected
        }

        fn get_program(&self) -> Box<dyn Program> {
            Box::new(MockProgram)
        }
    }

    impl DecompilerProvider for MockProvider {
        fn get_tool(&self) -> Arc<dyn PluginTool> {
            Arc::new(MockTool)
        }

        fn get_decompiler_panel(&self) -> Box<dyn DecompilerPanel> {
            Box::new(self.panel.clone())
        }

        fn get_controller(&self) -> Box<dyn DecompilerController> {
            Box::new(MockController)
        }

        fn get_text_selection(&self) -> String {
            self.text_selection.clone()
        }
    }

    fn provider(has_token: bool, text_selection: &str, connected: bool) -> Arc<dyn DecompilerProvider> {
        Arc::new(MockProvider {
            panel: CountingPanel { calls: Arc::new(AtomicU32::new(0)), has_token },
            text_selection: text_selection.to_string(),
            connected,
        })
    }

    #[test]
    #[should_panic(expected = "lineNumber must be >= 0. Got -1")]
    fn new_rejects_negative_line_number() {
        DecompilerActionContext::new(provider(false, "", true), None, false, -1);
    }

    #[test]
    fn with_current_line_defaults_line_number_to_zero() {
        let ctx = DecompilerActionContext::with_current_line(provider(false, "", true), None, false);
        // With no token at the cursor and lineNumber == 0, Java's getLineNumber() falls back to 0.
        assert_eq!(ctx.get_line_number(), 0);
    }

    #[test]
    fn get_line_number_prefers_explicit_line_number_over_the_cursor_token() {
        // A token is available (on line 7), but an explicit non-zero line number always wins,
        // mirroring `if (lineNumber != 0) return lineNumber;`.
        let ctx = DecompilerActionContext::new(provider(true, "", true), None, false, 42);
        assert_eq!(ctx.get_line_number(), 42);
    }

    #[test]
    fn get_line_number_falls_back_to_the_cursor_tokens_line() {
        let ctx = DecompilerActionContext::with_current_line(provider(true, "", true), None, false);
        assert_eq!(ctx.get_line_number(), 7);
    }

    #[test]
    fn get_token_at_cursor_only_queries_the_panel_once() {
        let calls = Arc::new(AtomicU32::new(0));
        let provider: Arc<dyn DecompilerProvider> = Arc::new(MockProvider {
            panel: CountingPanel { calls: calls.clone(), has_token: true },
            text_selection: String::new(),
            connected: true,
        });
        let ctx = DecompilerActionContext::with_current_line(provider, None, false);

        // Java's tokenIsInitialized guard means getDecompilerPanel().getTokenAtCursor() is only
        // ever invoked once, no matter how many times getTokenAtCursor() is called.
        assert!(ctx.get_token_at_cursor().is_some());
        assert!(ctx.get_token_at_cursor().is_some());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn has_real_function_is_false_when_the_controller_has_no_function() {
        let ctx = DecompilerActionContext::with_current_line(provider(false, "", true), None, false);
        assert!(!ctx.has_real_function());
    }

    #[test]
    fn has_selection_is_false_for_blank_text_selection() {
        let ctx = DecompilerActionContext::with_current_line(provider(false, "   ", true), None, false);
        assert!(!ctx.has_selection());
    }

    #[test]
    fn has_selection_is_true_for_nonblank_text_selection() {
        let ctx = DecompilerActionContext::with_current_line(provider(false, "int x", true), None, false);
        assert!(ctx.has_selection());
    }

    #[test]
    fn is_active_program_reflects_the_navigatables_connection() {
        let connected = DecompilerActionContext::with_current_line(provider(false, "", true), None, false);
        assert!(connected.is_active_program());

        let disconnected = DecompilerActionContext::with_current_line(provider(false, "", false), None, false);
        assert!(!disconnected.is_active_program());
    }

    #[test]
    fn get_function_for_location_is_none_without_a_cursor_token() {
        let ctx = DecompilerActionContext::with_current_line(provider(false, "", true), None, false);
        assert!(ctx.get_function_for_location().is_none());
    }

    #[test]
    fn get_function_for_location_is_none_for_a_non_func_name_token() {
        // CountingPanel's token has ClangTokenKind::Generic, not ClangTokenKind::FuncName, so the
        // `instanceof ClangFuncNameToken` check (see ClangToken::kind) rejects it before
        // DecompilerUtils::get_function would ever be called.
        let ctx = DecompilerActionContext::with_current_line(provider(true, "", true), None, false);
        assert!(ctx.get_function_for_location().is_none());
    }

    #[test]
    fn get_tool_forwards_through_the_component_provider() {
        let ctx = DecompilerActionContext::with_current_line(provider(false, "", true), None, false);
        let _tool = ctx.get_tool();
    }
}
