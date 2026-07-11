//! Service for providing block models.
//!
//! Port of `ghidra.app.services.BlockModelService`. The Java `@ServiceInfo` annotation has no
//! Rust equivalent and is omitted.
//!
//! Java's `Class<? extends CodeBlockModel>` (used to register/unregister a model implementation)
//! has no Rust equivalent, since Rust has no reflective `Class` object; it is represented here as
//! a [`CodeBlockModelFactory`] function pointer that constructs a fresh model instance, which is
//! how the service is actually used (registration + later instantiation). `CodeBlockModel` is not
//! yet ported, so it is represented by a placeholder trait in [`crate::app::seam_stubs`]. Java's
//! overloaded `getActiveBlockModel`/`getActiveSubroutineModel`/`getNewModelByName` methods are
//! given distinct Rust names, since Rust traits cannot overload on parameter type/arity alone.

use crate::app::seam_stubs::CodeBlockModel;
use crate::app::services::BlockModelServiceListener;
use crate::program::model::listing::Program;
use crate::util::exception::NotFoundException;

/// Type for a simple block model.
///
/// Port of `BlockModelService.BASIC_MODEL`. See `ghidra.program.model.block.SimpleBlockModel`.
pub const BASIC_MODEL: i32 = 1;

/// Type for a subroutine block model.
///
/// Port of `BlockModelService.SUBROUTINE_MODEL`.
pub const SUBROUTINE_MODEL: i32 = 2;

/// Name of the implementation for a Simple block model.
///
/// Port of `BlockModelService.SIMPLE_BLOCK_MODEL_NAME` (`SimpleBlockModel.NAME`).
pub const SIMPLE_BLOCK_MODEL_NAME: &str = "Simple Block";

/// Name of the implementation for a subroutine with multiple entry points.
///
/// Port of `BlockModelService.MULTI_ENTRY_SUBROUTINE_MODEL_NAME` (`MultEntSubModel.NAME`).
pub const MULTI_ENTRY_SUBROUTINE_MODEL_NAME: &str = "Multiple Entry";

/// Name of the implementation for a subroutine that has a unique entry point, which may share
/// code with other subroutines.
///
/// Port of `BlockModelService.ISOLATED_ENTRY_SUBROUTINE_MODEL_NAME`
/// (`IsolatedEntrySubModel.ISOLATED_MODEL_NAME`).
pub const ISOLATED_ENTRY_SUBROUTINE_MODEL_NAME: &str = "Isolated Entry";

/// Name of the implementation for an overlapped subroutine model.
///
/// Port of `BlockModelService.OVERLAPPED_SUBROUTINE_MODEL_NAME`
/// (`OverlapCodeSubModel.OVERLAP_MODEL_NAME`).
pub const OVERLAPPED_SUBROUTINE_MODEL_NAME: &str = "Overlapped Code";

/// Name of the implementation for a subroutine that does not share code with other subroutines
/// and may have one or more entry points.
///
/// Port of `BlockModelService.PARTITIONED_SUBROUTINE_MODEL_NAME` (`PartitionCodeSubModel.NAME`).
pub const PARTITIONED_SUBROUTINE_MODEL_NAME: &str = "Partitioned Code";

/// Default basic block model (Simple Block Model).
///
/// Port of `BlockModelService.DEFAULT_BLOCK_MODEL_NAME`.
pub const DEFAULT_BLOCK_MODEL_NAME: &str = SIMPLE_BLOCK_MODEL_NAME;

/// Default subroutine model (M-Model).
///
/// Port of `BlockModelService.DEFAULT_SUBROUTINE_MODEL_NAME`.
pub const DEFAULT_SUBROUTINE_MODEL_NAME: &str = MULTI_ENTRY_SUBROUTINE_MODEL_NAME;

/// Constructs a new instance of a registered [`CodeBlockModel`] implementation.
///
/// Stands in for Java's `Class<? extends CodeBlockModel>`, used as the registration key and
/// factory for [`BlockModelService::register_model`]/[`BlockModelService::unregister_model`].
pub type CodeBlockModelFactory = fn() -> Box<dyn CodeBlockModel>;

/// Service for providing block models.
///
/// Port of `ghidra.app.services.BlockModelService`.
pub trait BlockModelService {
    /// Register a new model.
    ///
    /// Subroutine models must implement the `SubroutineBlockModel` interface - all other models
    /// are assumed to be basic block models.
    ///
    /// Port of `BlockModelService.registerModel(Class, String)`.
    fn register_model(&mut self, model_factory: CodeBlockModelFactory, model_name: &str);

    /// Deregister a model.
    ///
    /// Port of `BlockModelService.unregisterModel(Class)`.
    fn unregister_model(&mut self, model_factory: CodeBlockModelFactory);

    /// Get new instance of the active Basic Block model for the current program.
    ///
    /// Returns `None` if program is not open.
    ///
    /// Port of `BlockModelService.getActiveBlockModel()`.
    #[deprecated(note = "use get_active_block_model_for_program instead")]
    fn get_active_block_model(&self) -> Option<Box<dyn CodeBlockModel>>;

    /// Get new instance of the active Basic Block model for the current program.
    ///
    /// `include_externals`: externals are included if true. Returns `None` if program is not
    /// open.
    ///
    /// Port of `BlockModelService.getActiveBlockModel(boolean)`.
    #[deprecated(note = "use get_active_block_model_for_program_with_externals instead")]
    fn get_active_block_model_with_externals(
        &self,
        include_externals: bool,
    ) -> Option<Box<dyn CodeBlockModel>>;

    /// Get new instance of the active Basic Block model.
    ///
    /// Returns `None` if `program` is null in Java; here always associated with `program`.
    ///
    /// Port of `BlockModelService.getActiveBlockModel(Program)`.
    fn get_active_block_model_for_program(
        &self,
        program: &dyn Program,
    ) -> Option<Box<dyn CodeBlockModel>>;

    /// Get new instance of the active Basic Block model.
    ///
    /// `include_externals`: externals are included if true.
    ///
    /// Port of `BlockModelService.getActiveBlockModel(Program, boolean)`.
    fn get_active_block_model_for_program_with_externals(
        &self,
        program: &dyn Program,
        include_externals: bool,
    ) -> Option<Box<dyn CodeBlockModel>>;

    /// Get the name of the active Basic Block model.
    ///
    /// Port of `BlockModelService.getActiveBlockModelName()`.
    fn get_active_block_model_name(&self) -> String;

    /// Get new instance of the active Subroutine Block model for the current program.
    ///
    /// Returns `None` if program is not open.
    ///
    /// Port of `BlockModelService.getActiveSubroutineModel()`.
    #[deprecated(note = "use get_active_subroutine_model_for_program instead")]
    fn get_active_subroutine_model(&self) -> Option<Box<dyn CodeBlockModel>>;

    /// Get new instance of the active Subroutine Block model for the current program.
    ///
    /// `include_externals`: externals are included if true. Returns `None` if program is not
    /// open.
    ///
    /// Port of `BlockModelService.getActiveSubroutineModel(boolean)`.
    #[deprecated(note = "use get_active_subroutine_model_for_program instead")]
    fn get_active_subroutine_model_with_externals(
        &self,
        include_externals: bool,
    ) -> Option<Box<dyn CodeBlockModel>>;

    /// Get new instance of the active Subroutine Block model.
    ///
    /// Port of `BlockModelService.getActiveSubroutineModel(Program)`.
    fn get_active_subroutine_model_for_program(
        &self,
        program: &dyn Program,
    ) -> Option<Box<dyn CodeBlockModel>>;

    /// Get new instance of the active Subroutine Block model.
    ///
    /// `include_externals`: externals are included if true.
    ///
    /// Port of `BlockModelService.getActiveSubroutineModel(Program, boolean)`.
    fn get_active_subroutine_model_for_program_with_externals(
        &self,
        program: &dyn Program,
        include_externals: bool,
    ) -> Option<Box<dyn CodeBlockModel>>;

    /// Get the name of the active Subroutine model.
    ///
    /// Port of `BlockModelService.getActiveSubroutineModelName()`.
    fn get_active_subroutine_model_name(&self) -> String;

    /// Get new instance of the specified block model.
    ///
    /// Returns `None` if program is not open.
    ///
    /// # Errors
    ///
    /// Returns a `NotFoundException` if the specified model is not registered.
    ///
    /// Port of `BlockModelService.getNewModelByName(String)`.
    #[deprecated(note = "use get_new_model_by_name_for_program instead")]
    fn get_new_model_by_name(
        &self,
        model_name: &str,
    ) -> Result<Option<Box<dyn CodeBlockModel>>, NotFoundException>;

    /// Get new instance of the specified block model.
    ///
    /// `include_externals`: externals are included if true. Returns `None` if program is not
    /// open.
    ///
    /// # Errors
    ///
    /// Returns a `NotFoundException` if the specified model is not registered.
    ///
    /// Port of `BlockModelService.getNewModelByName(String, boolean)`.
    #[deprecated(note = "use get_new_model_by_name_for_program_with_externals instead")]
    fn get_new_model_by_name_with_externals(
        &self,
        model_name: &str,
        include_externals: bool,
    ) -> Result<Option<Box<dyn CodeBlockModel>>, NotFoundException>;

    /// Get new instance of the specified block model.
    ///
    /// # Errors
    ///
    /// Returns a `NotFoundException` if the specified model is not registered.
    ///
    /// Port of `BlockModelService.getNewModelByName(String, Program)`.
    fn get_new_model_by_name_for_program(
        &self,
        model_name: &str,
        program: &dyn Program,
    ) -> Result<Option<Box<dyn CodeBlockModel>>, NotFoundException>;

    /// Get new instance of the specified block model.
    ///
    /// `include_externals`: externals are included if true.
    ///
    /// # Errors
    ///
    /// Returns a `NotFoundException` if the specified model is not registered.
    ///
    /// Port of `BlockModelService.getNewModelByName(String, Program, boolean)`.
    fn get_new_model_by_name_for_program_with_externals(
        &self,
        model_name: &str,
        program: &dyn Program,
        include_externals: bool,
    ) -> Result<Option<Box<dyn CodeBlockModel>>, NotFoundException>;

    /// Get list of registered block models of the specified type.
    ///
    /// A `model_type` of `ANY_BLOCK` will return all models registered. List ordering is based
    /// upon the registration order. It is important to recognize that the list of returned names
    /// could change as models are registered and unregistered.
    ///
    /// Port of `BlockModelService.getAvailableModelNames(int)`.
    fn get_available_model_names(&self, model_type: i32) -> Vec<String>;

    /// Add service listener.
    ///
    /// Port of `BlockModelService.addListener(BlockModelServiceListener)`.
    fn add_listener(&mut self, listener: Box<dyn BlockModelServiceListener>);

    /// Remove service listener.
    ///
    /// Port of `BlockModelService.removeListener(BlockModelServiceListener)`.
    fn remove_listener(&mut self, listener: &dyn BlockModelServiceListener);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockModel;
    impl CodeBlockModel for MockModel {}

    fn make_mock_model() -> Box<dyn CodeBlockModel> {
        Box::new(MockModel)
    }

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:64:default".to_string()
        }
    }

    struct MockListener;
    impl BlockModelServiceListener for MockListener {
        fn model_added(&self, _model_name: &str, _model_type: i32) {}
        fn model_removed(&self, _model_name: &str, _model_type: i32) {}
    }

    struct MockService {
        registered: Vec<(CodeBlockModelFactory, String)>,
        listener_count: usize,
    }

    #[allow(deprecated)]
    impl BlockModelService for MockService {
        fn register_model(&mut self, model_factory: CodeBlockModelFactory, model_name: &str) {
            self.registered.push((model_factory, model_name.to_string()));
        }

        fn unregister_model(&mut self, model_factory: CodeBlockModelFactory) {
            self.registered.retain(|(f, _)| *f != model_factory);
        }

        fn get_active_block_model(&self) -> Option<Box<dyn CodeBlockModel>> {
            Some(make_mock_model())
        }

        fn get_active_block_model_with_externals(
            &self,
            _include_externals: bool,
        ) -> Option<Box<dyn CodeBlockModel>> {
            Some(make_mock_model())
        }

        fn get_active_block_model_for_program(
            &self,
            _program: &dyn Program,
        ) -> Option<Box<dyn CodeBlockModel>> {
            Some(make_mock_model())
        }

        fn get_active_block_model_for_program_with_externals(
            &self,
            _program: &dyn Program,
            _include_externals: bool,
        ) -> Option<Box<dyn CodeBlockModel>> {
            Some(make_mock_model())
        }

        fn get_active_block_model_name(&self) -> String {
            DEFAULT_BLOCK_MODEL_NAME.to_string()
        }

        fn get_active_subroutine_model(&self) -> Option<Box<dyn CodeBlockModel>> {
            Some(make_mock_model())
        }

        fn get_active_subroutine_model_with_externals(
            &self,
            _include_externals: bool,
        ) -> Option<Box<dyn CodeBlockModel>> {
            Some(make_mock_model())
        }

        fn get_active_subroutine_model_for_program(
            &self,
            _program: &dyn Program,
        ) -> Option<Box<dyn CodeBlockModel>> {
            Some(make_mock_model())
        }

        fn get_active_subroutine_model_for_program_with_externals(
            &self,
            _program: &dyn Program,
            _include_externals: bool,
        ) -> Option<Box<dyn CodeBlockModel>> {
            Some(make_mock_model())
        }

        fn get_active_subroutine_model_name(&self) -> String {
            DEFAULT_SUBROUTINE_MODEL_NAME.to_string()
        }

        fn get_new_model_by_name(
            &self,
            model_name: &str,
        ) -> Result<Option<Box<dyn CodeBlockModel>>, NotFoundException> {
            self.get_new_model_by_name_with_externals(model_name, false)
        }

        fn get_new_model_by_name_with_externals(
            &self,
            model_name: &str,
            _include_externals: bool,
        ) -> Result<Option<Box<dyn CodeBlockModel>>, NotFoundException> {
            if self.registered.iter().any(|(_, name)| name == model_name) {
                Ok(Some(make_mock_model()))
            } else {
                Err(NotFoundException::with_message(model_name))
            }
        }

        fn get_new_model_by_name_for_program(
            &self,
            model_name: &str,
            program: &dyn Program,
        ) -> Result<Option<Box<dyn CodeBlockModel>>, NotFoundException> {
            self.get_new_model_by_name_for_program_with_externals(model_name, program, false)
        }

        fn get_new_model_by_name_for_program_with_externals(
            &self,
            model_name: &str,
            _program: &dyn Program,
            _include_externals: bool,
        ) -> Result<Option<Box<dyn CodeBlockModel>>, NotFoundException> {
            if self.registered.iter().any(|(_, name)| name == model_name) {
                Ok(Some(make_mock_model()))
            } else {
                Err(NotFoundException::with_message(model_name))
            }
        }

        fn get_available_model_names(&self, _model_type: i32) -> Vec<String> {
            self.registered.iter().map(|(_, name)| name.clone()).collect()
        }

        fn add_listener(&mut self, _listener: Box<dyn BlockModelServiceListener>) {
            self.listener_count += 1;
        }

        fn remove_listener(&mut self, _listener: &dyn BlockModelServiceListener) {
            self.listener_count -= 1;
        }
    }

    #[test]
    #[allow(deprecated)]
    fn is_object_safe_as_boxed_trait() {
        let mut service: Box<dyn BlockModelService> = Box::new(MockService {
            registered: Vec::new(),
            listener_count: 0,
        });

        service.register_model(make_mock_model, SIMPLE_BLOCK_MODEL_NAME);
        assert_eq!(
            service.get_available_model_names(BASIC_MODEL),
            vec![SIMPLE_BLOCK_MODEL_NAME.to_string()]
        );

        assert!(service
            .get_new_model_by_name_for_program(SIMPLE_BLOCK_MODEL_NAME, &MockProgram)
            .is_ok());
        assert!(service
            .get_new_model_by_name_for_program("missing", &MockProgram)
            .is_err());

        assert_eq!(service.get_active_block_model_name(), DEFAULT_BLOCK_MODEL_NAME);
        assert_eq!(
            service.get_active_subroutine_model_name(),
            DEFAULT_SUBROUTINE_MODEL_NAME
        );
        assert!(service.get_active_block_model().is_some());
        assert!(service
            .get_active_block_model_for_program(&MockProgram)
            .is_some());
        assert!(service
            .get_active_subroutine_model_for_program(&MockProgram)
            .is_some());

        service.add_listener(Box::new(MockListener));
        service.remove_listener(&MockListener);

        service.unregister_model(make_mock_model);
        assert!(service.get_available_model_names(BASIC_MODEL).is_empty());
    }
}
