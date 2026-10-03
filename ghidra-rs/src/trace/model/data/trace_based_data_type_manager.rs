use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_conflict_handler::DataTypeConflictHandler;
use crate::program::model::data::data_type_manager::ReplaceDataTypeError;
use crate::program::model::data::program_based_data_type_manager::ProgramBasedDataTypeManager;
use crate::trace::model::guest::trace_platform::TracePlatform;
use crate::trace::model::program::trace_variable_snap_program_view::TraceVariableSnapProgramView;
use crate::trace::model::trace::Trace;

/// A data type manager which is part of a [`Trace`].
///
/// Port of `ghidra.trace.model.data.TraceBasedDataTypeManager`.
///
/// The Java interface `extends ProgramBasedDataTypeManager`, and its `default getProgram()`
/// covariantly narrows the inherited abstract `ProgramBasedDataTypeManager.getProgram()` (which
/// returns `Program`) down to `TraceProgramView`. Rust has no covariant trait-method override --
/// the same issue documented throughout this crate's DB-backed trace types (see
/// [`DBTraceDataAdapter`](crate::trace::database::listing::db_trace_data_adapter::DBTraceDataAdapter)'s
/// docs) -- so [`get_program`](Self::get_program) here is a *new*, separately dispatched method
/// of the same name, not an override of
/// [`ProgramBasedDataTypeManager::get_program`]; a `ProgramBasedDataTypeManager` impl that wants
/// this behavior should delegate its body to this trait's version, and a caller holding a
/// `&dyn TraceBasedDataTypeManager` must disambiguate with UFCS (e.g.
/// `TraceBasedDataTypeManager::get_program(&x)`) if `ProgramBasedDataTypeManager` is also in
/// scope. It returns `Box<dyn TraceVariableSnapProgramView>` (what
/// [`Trace::get_program_view`] actually produces) rather than the less specific
/// `Box<dyn TraceProgramView>` the Java signature names, since `TraceVariableSnapProgramView:
/// TraceProgramView` and this crate has no trait-object upcast for the wider box.
///
/// `resolveType`/`addType`/`replaceType` are Java generics that unchecked-cast the erased
/// `DataType` result back to the caller's `T extends DataType`; since
/// [`DataType`](crate::program::model::data::data_type::DataType) here is not downcastable from a
/// `dyn DataType` (there is no `Any` bound), these keep the same type-erased `Box<dyn DataType>`
/// signature [`DataTypeManager::resolve`]/[`add_data_type`]/[`replace_data_type`] already use --
/// a caller that needs the narrower type must downcast at the same place it would in Java anyway
/// (the cast there is unchecked and erased at runtime).
///
/// [`ProgramBasedDataTypeManager::get_program`]: crate::program::model::data::program_based_data_type_manager::ProgramBasedDataTypeManager::get_program
/// [`Trace::get_program_view`]: crate::trace::model::trace::Trace::get_program_view
/// [`DataTypeManager::resolve`]: crate::program::model::data::data_type_manager::DataTypeManager::resolve
/// [`add_data_type`]: crate::program::model::data::data_type_manager::DataTypeManager::add_data_type
/// [`replace_data_type`]: crate::program::model::data::data_type_manager::DataTypeManager::replace_data_type
pub trait TraceBasedDataTypeManager: ProgramBasedDataTypeManager {
    /// Get the trace of which this data type manager is a part.
    fn get_trace(&self) -> Box<dyn Trace>;

    /// Get the platform for which this data type manager is provided.
    fn get_platform(&self) -> Box<dyn TracePlatform>;

    /// Mirrors the `default getProgram()` override. See the trait's own docs for why this is a
    /// new method rather than an override of
    /// [`ProgramBasedDataTypeManager::get_program`](crate::program::model::data::program_based_data_type_manager::ProgramBasedDataTypeManager::get_program).
    fn get_program(&self) -> Box<dyn TraceVariableSnapProgramView> {
        self.get_trace().get_program_view()
    }

    /// Mirrors `resolveType`: resolves `data_type` into this manager, returning the type-erased
    /// result. See the trait's own docs for why this does not restore the caller's original
    /// `DataType` subtype the way Java's unchecked cast pretends to.
    fn resolve_type(
        &mut self,
        data_type: Box<dyn DataType>,
        handler: &dyn DataTypeConflictHandler,
    ) -> Box<dyn DataType> {
        self.resolve(data_type, handler)
    }

    /// Mirrors `addType`: adds `data_type` to this manager, returning the type-erased result.
    fn add_type(
        &mut self,
        data_type: Box<dyn DataType>,
        handler: &dyn DataTypeConflictHandler,
    ) -> Box<dyn DataType> {
        self.add_data_type(data_type, handler)
    }

    /// Mirrors `replaceType`: replaces `existing_dt` with `replacement_dt`, returning the
    /// type-erased result.
    fn replace_type(
        &mut self,
        existing_dt: &dyn DataType,
        replacement_dt: Box<dyn DataType>,
        update_category_path: bool,
    ) -> Result<Box<dyn DataType>, ReplaceDataTypeError> {
        self.replace_data_type(existing_dt, replacement_dt, update_category_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;
    use std::sync::Arc;

    use crate::docking::settings::settings_definition::SettingsDefinition;
    use crate::framework::model::DomainFile;
    use crate::program::model::address::Address;
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::data::domain_file_based_data_type_manager::DomainFileBasedDataTypeManager;
    use crate::program::model::data::file_based_data_type_manager::FileBasedDataTypeManager;
    use crate::program::model::listing::data::Data;
    use crate::program::model::listing::program::Program;
    use crate::trace::model::program::trace_program_view::TraceProgramView;
    use crate::util::exception::CancelledException;
    use crate::util::task::TaskMonitor;

    /// A `TraceBasedDataTypeManager` whose only real behavior is `get_data_types_added`, used to
    /// verify `resolve_type`/`add_type`/`replace_type` delegate to the `DataTypeManager` methods
    /// of the same underlying erased operation rather than reimplementing them.
    struct MockManager {
        resolved: Vec<String>,
    }

    impl DataTypeManager for MockManager {
        fn resolve(
            &mut self,
            data_type: Box<dyn DataType>,
            _handler: &dyn DataTypeConflictHandler,
        ) -> Box<dyn DataType> {
            self.resolved.push(data_type.get_name());
            data_type
        }
    }

    impl FileBasedDataTypeManager for MockManager {
        fn get_path(&self) -> String {
            "/mock".to_string()
        }
    }

    impl DomainFileBasedDataTypeManager for MockManager {
        fn get_domain_file(&self) -> Box<dyn DomainFile> {
            unimplemented!("not exercised by these tests")
        }
    }

    impl ProgramBasedDataTypeManager for MockManager {
        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not exercised by these tests")
        }
        fn is_change_allowed(&self, _data: &dyn Data, _settings_definition: &dyn SettingsDefinition) -> bool {
            true
        }
        fn set_long_settings_value(&mut self, _data: &dyn Data, _name: &str, _value: i64) -> bool {
            false
        }
        fn set_string_settings_value(&mut self, _data: &dyn Data, _name: &str, _value: &str) -> bool {
            false
        }
        fn set_settings(&mut self, _data: &dyn Data, _name: &str, _value: Box<dyn Any>) -> bool {
            false
        }
        fn get_long_settings_value(&self, _data: &dyn Data, _name: &str) -> Option<i64> {
            None
        }
        fn get_string_settings_value(&self, _data: &dyn Data, _name: &str) -> Option<String> {
            None
        }
        fn get_settings(&self, _data: &dyn Data, _name: &str) -> Option<Box<dyn Any>> {
            None
        }
        fn clear_setting(&mut self, _data: &dyn Data, _name: &str) -> bool {
            false
        }
        fn clear_all_settings(&mut self, _data: &dyn Data) {}
        fn get_instance_settings_names(&self, _data: &dyn Data) -> Vec<String> {
            Vec::new()
        }
        fn is_empty_setting(&self, _data: &dyn Data) -> bool {
            true
        }
        fn move_address_range(
            &mut self,
            _from_addr: &Address,
            _to_addr: &Address,
            _length: i64,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Ok(())
        }
        fn delete_address_range(
            &mut self,
            _start_addr: &Address,
            _end_addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            Ok(())
        }
    }

    impl TraceBasedDataTypeManager for MockManager {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by these tests")
        }
        fn get_platform(&self) -> Box<dyn TracePlatform> {
            unimplemented!("not exercised by these tests")
        }
    }

    struct MockDataType {
        name: String,
    }

    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            self.name.clone()
        }
    }

    #[test]
    fn resolve_type_delegates_to_resolve() {
        let mut mgr = MockManager { resolved: Vec::new() };
        let dt: Box<dyn DataType> = Box::new(MockDataType { name: "int".to_string() });
        let result = TraceBasedDataTypeManager::resolve_type(
            &mut mgr,
            dt,
            &crate::program::model::data::data_type_conflict_handler::DEFAULT_HANDLER,
        );
        assert_eq!(result.get_name(), "int");
        assert_eq!(mgr.resolved, vec!["int".to_string()]);
    }

    #[test]
    fn add_type_delegates_to_add_data_type_which_delegates_to_resolve() {
        let mut mgr = MockManager { resolved: Vec::new() };
        let dt: Box<dyn DataType> = Box::new(MockDataType { name: "long".to_string() });
        let result = TraceBasedDataTypeManager::add_type(
            &mut mgr,
            dt,
            &crate::program::model::data::data_type_conflict_handler::DEFAULT_HANDLER,
        );
        assert_eq!(result.get_name(), "long");
        assert_eq!(mgr.resolved, vec!["long".to_string()]);
    }

    #[test]
    fn trait_is_object_safe() {
        fn _assert(_m: &dyn TraceBasedDataTypeManager) {}
    }
}
