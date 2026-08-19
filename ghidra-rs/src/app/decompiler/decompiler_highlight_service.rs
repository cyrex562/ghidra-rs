//! Port of `ghidra.app.decompiler.DecompilerHighlightService`.
//!
//! A service that allows clients to create highlights in the form of background colors for
//! `ClangToken`s in the Decompiler UI.
//!
//! Note: highlights apply to a full token and not strings of text. To highlight a token, create
//! an instance of [`CTokenHighlightMatcher`] to pass to one of the `create_highlighter` methods
//! of this trait.
//!
//! There is no limit to the number of highlighters that may be installed. If multiple highlights
//! overlap, then their colors will be blended. The number of color blends may be limited for
//! performance reasons.

use crate::app::decompiler::decompiler_highlighter::DecompilerHighlighter;
use crate::app::seam_stubs::CTokenHighlightMatcher;
use crate::program::model::listing::function::Function;

/// A service that creates [`DecompilerHighlighter`]s from token matchers.
///
/// This is a port of the Java interface `ghidra.app.decompiler.DecompilerHighlightService`.
/// Implementors need only provide the two `for_function` variants; the global (no explicit
/// function) variants are default methods that delegate with `function = None`, mirroring the
/// Java `default` methods on the original interface.
pub trait DecompilerHighlightService: Send + Sync {
    /// Creates a highlighter that will use the given matcher to create highlights as functions
    /// get decompiled. The highlighter created will be applied to every decompiled function.
    fn create_highlighter(
        &self,
        tm: &dyn CTokenHighlightMatcher,
    ) -> Box<dyn DecompilerHighlighter> {
        self.create_highlighter_for_function(None, tm)
    }

    /// Creates a highlighter that will use the given matcher to create highlights as functions
    /// get decompiled. The highlighter created will only be applied to `function`, or to every
    /// decompiled function if `function` is `None`.
    fn create_highlighter_for_function(
        &self,
        function: Option<&dyn Function>,
        tm: &dyn CTokenHighlightMatcher,
    ) -> Box<dyn DecompilerHighlighter>;

    /// A version of [`create_highlighter`](Self::create_highlighter) that allows clients to
    /// specify an ID. This ID is used to ensure that any existing highlighters with that ID are
    /// removed before creating a new highlighter. The highlighter created will be applied to
    /// every decompiled function.
    ///
    /// This is convenient for scripts, since a script cannot hold on to any created highlighters
    /// between repeated script executions. A good value for script writers to use is the name of
    /// their script class.
    fn create_highlighter_with_id(
        &self,
        id: &str,
        tm: &dyn CTokenHighlightMatcher,
    ) -> Box<dyn DecompilerHighlighter> {
        self.create_highlighter_with_id_for_function(id, None, tm)
    }

    /// A version of [`create_highlighter_for_function`](Self::create_highlighter_for_function)
    /// that allows clients to specify an ID. This ID is used to ensure that any existing
    /// highlighters with that ID are removed before creating a new highlighter. The highlighter
    /// created will only be applied to `function`, or to every decompiled function if `function`
    /// is `None`.
    fn create_highlighter_with_id_for_function(
        &self,
        id: &str,
        function: Option<&dyn Function>,
        tm: &dyn CTokenHighlightMatcher,
    ) -> Box<dyn DecompilerHighlighter>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::decompiler::clang_node::ClangNode;
    use std::sync::Mutex;

    struct RecordingHighlighter {
        id: String,
        applied: bool,
    }

    impl DecompilerHighlighter for RecordingHighlighter {
        fn apply_highlights(&mut self) {
            self.applied = true;
        }

        fn clear_highlights(&mut self) {
            self.applied = false;
        }

        fn dispose(&mut self) {}

        fn get_id(&self) -> &str {
            &self.id
        }
    }

    struct NoOpMatcher;

    impl CTokenHighlightMatcher for NoOpMatcher {
        fn start(&self, _root: &dyn ClangNode) {}
        fn end(&self) {}
        fn get_token_highlight(
            &self,
            _token: &dyn ClangNode,
        ) -> Box<dyn crate::app::seam_stubs::Color> {
            unimplemented!("not exercised by this test")
        }
    }

    /// A test service that records the id/function it was asked to scope a highlighter to,
    /// mirroring how a real implementation (e.g. the Decompiler plugin) would dispatch based on
    /// the ID and function scoping rules described in the Java interface's javadoc.
    struct TestHighlightService {
        last_id: Mutex<Option<String>>,
        last_function_seen: Mutex<bool>,
    }

    impl TestHighlightService {
        fn new() -> Self {
            Self { last_id: Mutex::new(None), last_function_seen: Mutex::new(false) }
        }
    }

    impl DecompilerHighlightService for TestHighlightService {
        fn create_highlighter_for_function(
            &self,
            function: Option<&dyn Function>,
            _tm: &dyn CTokenHighlightMatcher,
        ) -> Box<dyn DecompilerHighlighter> {
            *self.last_id.lock().unwrap() = None;
            *self.last_function_seen.lock().unwrap() = function.is_some();
            Box::new(RecordingHighlighter { id: "generated-id".to_string(), applied: false })
        }

        fn create_highlighter_with_id_for_function(
            &self,
            id: &str,
            function: Option<&dyn Function>,
            _tm: &dyn CTokenHighlightMatcher,
        ) -> Box<dyn DecompilerHighlighter> {
            *self.last_id.lock().unwrap() = Some(id.to_string());
            *self.last_function_seen.lock().unwrap() = function.is_some();
            Box::new(RecordingHighlighter { id: id.to_string(), applied: false })
        }
    }

    #[test]
    fn global_highlighter_defaults_to_no_function() {
        let service = TestHighlightService::new();
        let matcher = NoOpMatcher;

        let highlighter = service.create_highlighter(&matcher);

        assert_eq!(highlighter.get_id(), "generated-id");
        assert_eq!(*service.last_id.lock().unwrap(), None);
        assert!(!*service.last_function_seen.lock().unwrap());
    }

    #[test]
    fn id_variant_defaults_to_no_function_and_preserves_id() {
        let service = TestHighlightService::new();
        let matcher = NoOpMatcher;

        let highlighter = service.create_highlighter_with_id("my-script", &matcher);

        assert_eq!(highlighter.get_id(), "my-script");
        assert_eq!(*service.last_id.lock().unwrap(), Some("my-script".to_string()));
        assert!(!*service.last_function_seen.lock().unwrap());
    }

    #[test]
    fn service_usable_as_trait_object() {
        let service: Box<dyn DecompilerHighlightService> = Box::new(TestHighlightService::new());
        let matcher = NoOpMatcher;

        let highlighter = service.create_highlighter(&matcher);
        assert_eq!(highlighter.get_id(), "generated-id");
    }
}
