use std::sync::Arc;

use crate::app::seam_stubs::{FunctionComparisonModel, FunctionComparisonPanel};
use crate::program::model::listing::Function;
use crate::util::function::Callback;

/// Service interface to create comparisons between functions which will be displayed
/// side-by-side in a function comparison window. Each side in the display will allow the user to
/// select one or more functions.
///
/// Concurrent usage: In the Java original, all work performed by this service is done
/// asynchronously on the Swing thread.
///
/// Port of `ghidra.app.services.FunctionComparisonService`.
pub trait FunctionComparisonService {
    /// Creates a function comparison window where each side can display any of the given
    /// functions.
    ///
    /// * `functions` - the functions to compare
    fn create_comparison(&self, functions: &[Arc<dyn Function>]);

    /// Creates a function comparison window for the two given functions. Each side can select
    /// either function, but initially the left function will be shown in the left panel and the
    /// right function will be shown in the right panel.
    ///
    /// * `left` - the function to initially show in the left panel
    /// * `right` - the function to initially show in the right panel
    fn create_comparison_pair(&self, left: Arc<dyn Function>, right: Arc<dyn Function>);

    /// Adds the given function to each side the last created comparison window or creates a new
    /// comparison if none exists. The right panel will be changed to show the new function. Note
    /// that this method will not add to any provider created via
    /// [`create_custom_comparison`](Self::create_custom_comparison). Those providers are private
    /// to the client that created them. They take in a model, so if the client wants to add to
    /// those providers, it must retain a handle to the model and add functions directly to the
    /// model.
    ///
    /// * `function` - the function to be added to the last function comparison window
    fn add_to_comparison(&self, function: Arc<dyn Function>);

    /// Adds the given functions to each side the last created comparison window or creates a new
    /// comparison if none exists. The right panel will be change to show a random function from
    /// the new functions. Note that this method will not add to any comparison windows created
    /// with a custom comparison model.
    ///
    /// * `functions` - the functions to be added to the last function comparison window
    fn add_to_comparison_all(&self, functions: &[Arc<dyn Function>]);

    /// Creates a custom function comparison window. The default model shows all functions on
    /// both sides. This method allows the client to provide a custom comparison model which can
    /// have more control over what functions can be selected on each side. One such custom model
    /// is `MatchedFunctionComparisonModel`, which gives a unique set of functions on the right
    /// side, depending on what is selected on the left side.
    ///
    /// Note that function comparison windows created with this method are considered private for
    /// the client and are not available to be chosen for either of the above "add to" service
    /// methods. Instead, the client that uses this model can retain a handle to the model and add
    /// or remove functions directly on the model.
    ///
    /// * `model` - the custom function comparison model
    /// * `close_listener` - an optional callback if the client wants to be notified when the
    ///   associated function comparison windows is closed.
    fn create_custom_comparison(
        &self,
        model: Box<dyn FunctionComparisonModel>,
        close_listener: Option<Callback>,
    );

    /// Creates a new comparison view that the caller can install into their UI. This is in
    /// contrast with [`create_custom_comparison`](Self::create_custom_comparison), which will
    /// install the new comparison into an existing UI.
    ///
    /// Note: clients are responsible for disposing of the returned panel when done using it.
    ///
    /// Returns the new panel.
    fn create_comparison_viewer(&self) -> Box<dyn FunctionComparisonPanel>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeFunctionComparisonModel;
    impl FunctionComparisonModel for FakeFunctionComparisonModel {}

    struct FakeFunctionComparisonPanel;
    impl FunctionComparisonPanel for FakeFunctionComparisonPanel {}

    #[derive(Default)]
    struct FakeFunctionComparisonService {
        added: std::cell::RefCell<Vec<Arc<dyn Function>>>,
    }

    impl FunctionComparisonService for FakeFunctionComparisonService {
        fn create_comparison(&self, _functions: &[Arc<dyn Function>]) {}

        fn create_comparison_pair(&self, _left: Arc<dyn Function>, _right: Arc<dyn Function>) {}

        fn add_to_comparison(&self, function: Arc<dyn Function>) {
            self.added.borrow_mut().push(function);
        }

        fn add_to_comparison_all(&self, functions: &[Arc<dyn Function>]) {
            self.added.borrow_mut().extend(functions.iter().cloned());
        }

        fn create_custom_comparison(
            &self,
            _model: Box<dyn FunctionComparisonModel>,
            close_listener: Option<Callback>,
        ) {
            if let Some(cb) = close_listener {
                cb();
            }
        }

        fn create_comparison_viewer(&self) -> Box<dyn FunctionComparisonPanel> {
            Box::new(FakeFunctionComparisonPanel)
        }
    }

    #[test]
    fn is_object_safe_as_boxed_trait() {
        let service: Box<dyn FunctionComparisonService> =
            Box::new(FakeFunctionComparisonService::default());
        let _ = service;
    }

    #[test]
    fn create_custom_comparison_invokes_close_listener() {
        let service = FakeFunctionComparisonService::default();
        let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let called_clone = called.clone();
        service.create_custom_comparison(
            Box::new(FakeFunctionComparisonModel),
            Some(Box::new(move || {
                called_clone.store(true, std::sync::atomic::Ordering::SeqCst);
            })),
        );
        assert!(called.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn create_comparison_viewer_returns_panel() {
        let service = FakeFunctionComparisonService::default();
        let _panel = service.create_comparison_viewer();
    }
}
