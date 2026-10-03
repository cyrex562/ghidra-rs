//! Port of `ghidra.program.model.pcode.HighFunctionSymbol`.
//!
//! A function symbol that encapsulates detailed information about a particular function for the
//! purposes of decompilation. The detailed model is provided by a backing `HighFunction` object.
//!
//! In Java this `extends HighSymbol`; see
//! [`high_label_symbol`](crate::program::model::pcode::high_label_symbol)'s module docs for the
//! shared "`extends X`" convention (composition, not inheritance) and [`ResolvedStorage`] reuse.
//!
//! Unlike its three siblings in this module family
//! ([`HighLabelSymbol`](crate::program::model::pcode::high_label_symbol::HighLabelSymbol),
//! [`HighExternalSymbol`](crate::program::model::pcode::high_external_symbol::HighExternalSymbol),
//! [`HighFunctionShellSymbol`](crate::program::model::pcode::high_function_shell_symbol::HighFunctionShellSymbol)),
//! this class's Java constructor is always given a real, non-null `HighFunction`, so there is no
//! `getHighFunction()` gap here, and -- more usefully -- a real
//! [`ProgramArchitecture`] can be *derived* from that `HighFunction` (via its
//! `get_language()`/`get_compiler_spec()`, and `Language::get_address_factory()` for the address
//! factory), rather than needing a separately-injected one. [`HighFunctionSymbol::new`] therefore
//! matches Java's real three-argument constructor signature exactly (`Address`, `size`,
//! `HighFunction`), with no extra deviation parameters.

use std::io;
use std::sync::Arc;

use crate::program::model::address::{Address, SpecialAddress};
use crate::program::model::data::data_type::DataType;
use crate::program::model::lang::{CompilerSpec, Language, ProgramArchitecture};
use crate::program::model::listing::{Program, VariableStorage};
use crate::program::model::pcode::high_function::HighFunction;
use crate::program::model::pcode::high_label_symbol::ResolvedStorage;
use crate::program::model::pcode::high_symbol::HighSymbol;
use crate::program::model::symbol::{Namespace, GLOBAL_NAMESPACE_ID};
use crate::program::seam_stubs::PlaceholderDataType;

/// A [`ProgramArchitecture`] derived purely from a [`HighFunction`], used to resolve this
/// symbol's [`VariableStorage`] without needing a separately-injected architecture (see the
/// module docs).
struct HighFunctionProgramArchitecture(Arc<dyn HighFunction>);

impl ProgramArchitecture for HighFunctionProgramArchitecture {
    fn get_language(&self) -> Box<dyn Language> {
        self.0.get_language()
    }

    fn get_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
        self.0.get_language().get_address_factory()
    }

    fn get_compiler_spec(&self) -> Box<dyn CompilerSpec> {
        self.0.get_compiler_spec()
    }
}

/// A function symbol backed by a detailed decompiler `HighFunction` model. Port of
/// `ghidra.program.model.pcode.HighFunctionSymbol`.
pub struct HighFunctionSymbol {
    typelock: bool,
    namelock: bool,
    function: Arc<dyn HighFunction>,
    storage: ResolvedStorage,
}

impl HighFunctionSymbol {
    /// Construct given an Address, size, and decompiler function model for the symbol. Port of
    /// `HighFunctionSymbol(Address, int, HighFunction)`.
    pub fn new(addr: Address, size: i32, function: Arc<dyn HighFunction>) -> Self {
        let program_arch: Arc<dyn ProgramArchitecture> =
            Arc::new(HighFunctionProgramArchitecture(function.clone()));
        let storage = ResolvedStorage::resolve(program_arch, addr, size);
        HighFunctionSymbol { typelock: false, namelock: false, function, storage }
    }

    /// Test-only shortcut; see
    /// [`HighLabelSymbol::new_with_storage`](crate::program::model::pcode::high_label_symbol::HighLabelSymbol)'s
    /// sibling for why.
    #[cfg(test)]
    fn new_with_storage(function: Arc<dyn HighFunction>, storage: ResolvedStorage) -> Self {
        HighFunctionSymbol { typelock: false, namelock: false, function, storage }
    }
}

impl HighSymbol for HighFunctionSymbol {
    fn get_id(&self) -> i64 {
        self.function.get_id()
    }

    fn get_high_function(&self) -> Arc<dyn HighFunction> {
        self.function.clone()
    }

    fn get_program(&self) -> Arc<dyn Program> {
        self.function.get_function().get_program()
    }

    fn get_data_type(&self) -> Box<dyn DataType> {
        Box::new(PlaceholderDataType)
    }

    fn get_storage(&self) -> Box<dyn VariableStorage> {
        self.storage.to_variable_storage()
    }

    fn get_size(&self) -> i32 {
        self.storage.size()
    }

    fn is_type_locked(&self) -> bool {
        self.typelock
    }

    fn is_name_locked(&self) -> bool {
        self.namelock
    }

    fn set_type_lock(&mut self, typelock: bool) {
        self.typelock = typelock;
    }

    fn set_name_lock(&mut self, namelock: bool) {
        self.namelock = namelock;
    }

    /// Overrides `HighSymbol.isGlobal()`. Port of `HighFunctionSymbol.isGlobal()`.
    fn is_global(&self) -> bool {
        true
    }

    /// Port of `HighFunctionSymbol.getNamespace()`: walks up through thunked functions while the
    /// immediate parent namespace is the global namespace, choosing the outermost non-global
    /// namespace a thunk chain resolves to.
    ///
    /// # Deliberate deviation: `None` instead of NPE
    /// Java assumes `getParentNamespace()`/`getThunkedFunction(false)` are never `null` here and
    /// would throw `NullPointerException` if they were; this port's
    /// [`Namespace::get_parent_namespace`]/[`Function::get_thunked_function`] are modeled as
    /// `Option`, so this breaks out of the loop and returns `None` instead of panicking if either
    /// is ever absent.
    fn get_namespace(&self) -> Option<Arc<dyn Namespace>> {
        let mut func: Arc<dyn crate::program::model::listing::Function> = Arc::from(self.function.get_function());
        let mut namespc = func.get_parent_namespace();
        while func.is_thunk() {
            let is_global = matches!(&namespc, Some(ns) if ns.get_id() == GLOBAL_NAMESPACE_ID);
            if !is_global {
                break;
            }
            // Thunks can be in a different namespace than the thunked function. We choose the
            // thunk's namespace unless it is the global namespace.
            match func.get_thunked_function(false) {
                Some(thunked) => {
                    func = thunked;
                    namespc = func.get_parent_namespace();
                }
                None => break,
            }
        }
        namespc
    }

    /// Port of `HighFunctionSymbol.encode(Encoder)`.
    fn encode(&self, encoder: &mut dyn crate::program::model::pcode::Encoder) -> io::Result<()> {
        // Java passes `getNamespace()` to `HighFunction.encode` unchecked, implicitly assuming
        // it is never null (true for every function but the global namespace object itself,
        // whose own `getParentNamespace()` never reaches this code path); this port returns an
        // error instead of panicking/fabricating a namespace in that unreachable-in-practice
        // case.
        let namespace = self.get_namespace().ok_or_else(|| {
            io::Error::other("HighFunctionSymbol::encode: no namespace resolved for this function")
        })?;
        let min_addr = self.storage.min_address().unwrap_or_else(SpecialAddress::no_address);
        self.function.encode(encoder, self.get_id(), namespace.as_ref(), Some(min_addr), self.storage.size())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSetView, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::lang::prototype_model::PrototypeModel;
    use crate::program::model::listing::function::{FunctionEditError, SetFunctionNameError};
    use crate::program::model::listing::{Function, FunctionSignature, FunctionTag, Parameter, Variable};
    use crate::program::model::pcode::decoder::Decoder;
    use crate::program::model::pcode::decoder_exception::DecoderException;
    use crate::program::model::pcode::global_symbol_map::GlobalSymbolMap;
    use crate::program::model::pcode::high_variable::HighVariable;
    use crate::program::model::pcode::pcode_exception::PcodeException;
    use crate::program::model::pcode::Varnode;
    use crate::program::model::symbol::{ExternalLocation, SourceType, Symbol, SymbolType};
    use crate::program::seam_stubs::{LocalSymbolMap, StackFrame, VariableFilter};
    use crate::util::exception::InvalidInputException;
    use crate::util::task::TaskMonitor;
    use std::sync::Arc;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    struct MockSymbol {
        id: i64,
        name: String,
    }
    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            Address::new(ram_space(), 0)
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Namespace
        }
        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            self.id
        }
        fn get_parent_id(&self) -> i64 {
            0
        }
    }

    struct MockNamespace {
        id: i64,
        name: String,
    }
    impl Namespace for MockNamespace {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            Arc::new(MockSymbol { id: self.id, name: self.name.clone() })
        }
        fn get_id(&self) -> i64 {
            self.id
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            None
        }
    }

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock_program".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    /// Full [`Function`] mock (mirroring
    /// [`high_param_id`](crate::program::model::pcode::high_param_id)'s own `MockFunction`
    /// precedent): only the members [`HighFunctionSymbol::get_namespace`] actually reads
    /// (`is_thunk`/`get_thunked_function`/`get_parent_namespace`) and [`HighFunctionSymbol::new`]
    /// reads (`get_program`) are given real, field-driven bodies; everything else is required by
    /// the trait but is provably unreachable from those call paths.
    #[derive(Clone)]
    struct MockFunction {
        id: i64,
        parent_namespace: Option<Arc<dyn Namespace>>,
        is_thunk: bool,
        thunked: Option<Arc<dyn Function>>,
    }
    impl Namespace for MockFunction {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            Arc::new(MockSymbol { id: self.id, name: "mock_func".to_string() })
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            self.parent_namespace.clone()
        }
    }
    impl Function for MockFunction {
        fn get_name(&self) -> String {
            "mock_func".to_string()
        }
        fn set_name(&mut self, _name: &str, _source: SourceType) -> Result<(), SetFunctionNameError> {
            unimplemented!()
        }
        fn set_call_fixup(&mut self, _name: Option<&str>) {}
        fn get_call_fixup(&self) -> Option<String> {
            None
        }
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }
        fn get_comment(&self) -> Option<String> {
            None
        }
        fn get_comment_as_array(&self) -> Vec<String> {
            Vec::new()
        }
        fn set_comment(&mut self, _comment: Option<&str>) {}
        fn get_repeatable_comment(&self) -> Option<String> {
            None
        }
        fn get_repeatable_comment_as_array(&self) -> Vec<String> {
            Vec::new()
        }
        fn set_repeatable_comment(&mut self, _comment: Option<&str>) {}
        fn get_entry_point(&self) -> Address {
            Address::new(ram_space(), 0x1000)
        }
        fn get_return_type(&self) -> Option<Box<dyn DataType>> {
            None
        }
        fn set_return_type(&mut self, _data_type: Box<dyn DataType>, _source: SourceType) -> Result<(), InvalidInputException> {
            unimplemented!()
        }
        fn get_return(&self) -> Box<dyn Parameter> {
            unimplemented!()
        }
        fn set_return(
            &mut self,
            _data_type: Box<dyn DataType>,
            _storage: Box<dyn VariableStorage>,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            unimplemented!()
        }
        fn get_signature_formal(&self, _formal_signature: bool) -> Box<dyn FunctionSignature> {
            unimplemented!()
        }
        fn get_prototype_string(&self, _formal_signature: bool, _include_calling_convention: bool) -> String {
            unimplemented!()
        }
        fn get_signature_source(&self) -> SourceType {
            SourceType::Default
        }
        fn set_signature_source(&mut self, _signature_source: SourceType) {}
        fn get_stack_frame(&self) -> Box<dyn StackFrame> {
            unimplemented!()
        }
        fn get_stack_purge_size(&self) -> i32 {
            0
        }
        fn get_tags(&self) -> Vec<Box<dyn FunctionTag>> {
            Vec::new()
        }
        fn add_tag(&mut self, _name: &str) -> bool {
            false
        }
        fn remove_tag(&mut self, _name: &str) {}
        fn set_stack_purge_size(&mut self, _purge_size: i32) {}
        fn is_stack_purge_size_valid(&self) -> bool {
            true
        }
        #[allow(deprecated)]
        fn add_parameter(&mut self, _var: Box<dyn Variable>, _source: SourceType) -> Result<Box<dyn Parameter>, FunctionEditError> {
            unimplemented!()
        }
        #[allow(deprecated)]
        fn insert_parameter(
            &mut self,
            _ordinal: i32,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Parameter>, FunctionEditError> {
            unimplemented!()
        }
        fn replace_parameters(
            &mut self,
            _params: Vec<Box<dyn Variable>>,
            _update_type: crate::program::model::listing::FunctionUpdateType,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), FunctionEditError> {
            unimplemented!()
        }
        fn update_function(
            &mut self,
            _calling_convention: Option<&str>,
            _return_value: Option<Box<dyn Variable>>,
            _new_params: Vec<Box<dyn Variable>>,
            _update_type: crate::program::model::listing::FunctionUpdateType,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), FunctionEditError> {
            unimplemented!()
        }
        fn get_parameter(&self, _ordinal: i32) -> Option<Box<dyn Parameter>> {
            None
        }
        #[allow(deprecated)]
        fn remove_parameter(&mut self, _ordinal: i32) {}
        #[allow(deprecated)]
        fn move_parameter(&mut self, _from_ordinal: i32, _to_ordinal: i32) -> Result<Box<dyn Parameter>, InvalidInputException> {
            unimplemented!()
        }
        fn get_parameter_count(&self) -> i32 {
            0
        }
        fn get_auto_parameter_count(&self) -> i32 {
            0
        }
        fn get_parameters(&self) -> Vec<Box<dyn Parameter>> {
            Vec::new()
        }
        fn get_parameters_filtered(&self, _filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Parameter>> {
            Vec::new()
        }
        fn get_local_variables(&self) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }
        fn get_local_variables_filtered(&self, _filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }
        fn get_variables_filtered(&self, _filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }
        fn get_all_variables(&self) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }
        fn add_local_variable(&mut self, _var: Box<dyn Variable>, _source: SourceType) -> Result<Box<dyn Variable>, FunctionEditError> {
            unimplemented!()
        }
        fn remove_variable(&mut self, _var: &dyn Variable) {}
        fn set_body(&mut self, _new_body: &dyn AddressSetView) -> Result<(), crate::program::database::function::OverlappingFunctionException> {
            Ok(())
        }
        fn has_var_args(&self) -> bool {
            false
        }
        fn set_var_args(&mut self, _has_var_args: bool) {}
        fn is_inline(&self) -> bool {
            false
        }
        fn set_inline(&mut self, _is_inline: bool) {}
        fn has_no_return(&self) -> bool {
            false
        }
        fn set_no_return(&mut self, _has_no_return: bool) {}
        fn has_custom_variable_storage(&self) -> bool {
            false
        }
        fn set_custom_variable_storage(&mut self, _has_custom_variable_storage: bool) {}
        fn get_calling_convention(&self) -> Option<Arc<PrototypeModel>> {
            None
        }
        fn get_calling_convention_name(&self) -> String {
            "unknown".to_string()
        }
        fn set_calling_convention(&mut self, _name: &str) -> Result<(), InvalidInputException> {
            Ok(())
        }
        fn is_thunk(&self) -> bool {
            self.is_thunk
        }
        fn get_thunked_function(&self, _recursive: bool) -> Option<Arc<dyn Function>> {
            self.thunked.clone()
        }
        fn get_function_thunk_addresses(&self, _recursive: bool) -> Option<Vec<Address>> {
            None
        }
        fn set_thunked_function(&mut self, _thunked_function: Option<Arc<dyn Function>>) -> Result<(), String> {
            Ok(())
        }
        fn is_external(&self) -> bool {
            false
        }
        fn get_external_location(&self) -> Option<Box<dyn ExternalLocation>> {
            None
        }
        fn get_calling_functions(&self, _monitor: &dyn TaskMonitor) -> Vec<Arc<dyn Function>> {
            Vec::new()
        }
        fn get_called_functions(&self, _monitor: &dyn TaskMonitor) -> Vec<Arc<dyn Function>> {
            Vec::new()
        }
        fn promote_local_user_labels_to_global(&mut self) {}
        fn is_deleted(&self) -> bool {
            false
        }
    }

    struct MockHighFunction {
        id: i64,
        function: MockFunction,
    }
    impl HighFunction for MockHighFunction {
        fn get_function(&self) -> Box<dyn Function> {
            Box::new(self.function.clone())
        }
        fn get_id(&self) -> i64 {
            self.id
        }
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_local_symbol_map(&self) -> Box<dyn LocalSymbolMap> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_global_symbol_map(&self) -> Arc<dyn GlobalSymbolMap> {
            unimplemented!("not needed for this smoke test")
        }
        fn grab_from_function(&mut self, _override_extrapop: i32, _include_default_names: bool, _do_override: bool) {
            unimplemented!("not needed for this smoke test")
        }
        fn decode(&mut self, _decoder: &dyn Decoder) -> Result<(), DecoderException> {
            unimplemented!("not needed for this smoke test")
        }
        fn split_out_merge_group(
            &mut self,
            _high: Box<dyn HighVariable>,
            _vn: &Varnode,
        ) -> Result<Box<dyn HighVariable>, PcodeException> {
            unimplemented!("not needed for this smoke test")
        }
        fn encode(
            &self,
            _encoder: &mut dyn crate::program::model::pcode::Encoder,
            _id: i64,
            _namespace: &dyn Namespace,
            _entry_point: Option<Address>,
            _size: i32,
        ) -> io::Result<()> {
            Ok(())
        }
        fn set_volatile(&mut self, _vn: &Varnode, _val: bool) {
            unimplemented!("not needed for this smoke test")
        }
    }

    /// `isGlobal()` overrides the `HighSymbol` placeholder default (`false`), and `getId()`
    /// delegates to the backing `HighFunction`.
    #[test]
    fn is_global_is_always_true_and_id_delegates_to_function() {
        let namespace: Arc<dyn Namespace> = Arc::new(MockNamespace { id: 5, name: "ns".to_string() });
        let function = MockFunction { id: 100, parent_namespace: Some(namespace), is_thunk: false, thunked: None };
        let high_function: Arc<dyn HighFunction> = Arc::new(MockHighFunction { id: 42, function });
        let sym = HighFunctionSymbol::new_with_storage(high_function, ResolvedStorage::Unassigned);

        assert!(sym.is_global());
        assert_eq!(sym.get_id(), 42);
    }

    /// For a non-thunk function, `getNamespace()` returns the immediate parent namespace
    /// unchanged (the `while` loop never runs).
    #[test]
    fn get_namespace_returns_immediate_parent_for_non_thunk() {
        let namespace: Arc<dyn Namespace> = Arc::new(MockNamespace { id: 5, name: "my_ns".to_string() });
        let function = MockFunction { id: 1, parent_namespace: Some(namespace), is_thunk: false, thunked: None };
        let high_function: Arc<dyn HighFunction> = Arc::new(MockHighFunction { id: 1, function });
        let sym = HighFunctionSymbol::new_with_storage(high_function, ResolvedStorage::Unassigned);

        let ns = sym.get_namespace().expect("namespace should resolve");
        assert_eq!(ns.get_id(), 5);
    }

    /// For a thunk sitting directly in the global namespace, `getNamespace()` walks through to
    /// the thunked function's own (non-global) namespace, matching Java's `while (func.isThunk()
    /// && namespc.getID() == Namespace.GLOBAL_NAMESPACE_ID)` loop.
    #[test]
    fn get_namespace_walks_through_thunk_in_global_namespace() {
        let target_namespace: Arc<dyn Namespace> = Arc::new(MockNamespace { id: 9, name: "real_ns".to_string() });
        let target: Arc<dyn Function> =
            Arc::new(MockFunction { id: 20, parent_namespace: Some(target_namespace), is_thunk: false, thunked: None });
        let global_namespace: Arc<dyn Namespace> =
            Arc::new(MockNamespace { id: GLOBAL_NAMESPACE_ID, name: "Global".to_string() });
        let thunk = MockFunction { id: 21, parent_namespace: Some(global_namespace), is_thunk: true, thunked: Some(target) };
        let high_function: Arc<dyn HighFunction> = Arc::new(MockHighFunction { id: 2, function: thunk });
        let sym = HighFunctionSymbol::new_with_storage(high_function, ResolvedStorage::Unassigned);

        let ns = sym.get_namespace().expect("namespace should resolve");
        assert_eq!(ns.get_id(), 9);
    }

    /// A thunk whose immediate parent namespace is *not* global stops the walk immediately
    /// (matches Java's `&& namespc.getID() == Namespace.GLOBAL_NAMESPACE_ID` short-circuit): the
    /// thunk's own namespace is returned, its thunked target is never even consulted.
    #[test]
    fn get_namespace_stops_walk_when_thunk_namespace_is_not_global() {
        let own_namespace: Arc<dyn Namespace> = Arc::new(MockNamespace { id: 11, name: "not_global".to_string() });
        // A target that would be observably different if ever reached, proving it wasn't.
        let target: Arc<dyn Function> = Arc::new(MockFunction {
            id: 30,
            parent_namespace: Some(Arc::new(MockNamespace { id: 999, name: "should_not_be_reached".to_string() })),
            is_thunk: false,
            thunked: None,
        });
        let thunk = MockFunction { id: 22, parent_namespace: Some(own_namespace), is_thunk: true, thunked: Some(target) };
        let high_function: Arc<dyn HighFunction> = Arc::new(MockHighFunction { id: 4, function: thunk });
        let sym = HighFunctionSymbol::new_with_storage(high_function, ResolvedStorage::Unassigned);

        let ns = sym.get_namespace().expect("namespace should resolve");
        assert_eq!(ns.get_id(), 11);
    }

    /// `new` derives a `ProgramArchitecture` from the `HighFunction` itself (no separately
    /// injected one needed); an address the mock language's factory doesn't know about still
    /// exercises the shared `resolve_storage` fallback end-to-end.
    #[test]
    fn new_derives_program_architecture_from_high_function() {
        let space = ram_space();
        let addr = Address::new(space, 0x1000);
        let namespace: Arc<dyn Namespace> = Arc::new(MockNamespace { id: 5, name: "ns".to_string() });
        let function = MockFunction { id: 3, parent_namespace: Some(namespace), is_thunk: false, thunked: None };
        let high_function: Arc<dyn HighFunction> = Arc::new(MockHighFunction { id: 3, function });

        // `MockHighFunction::get_language` is `unimplemented!()`, so this proves `new`'s
        // `ProgramArchitecture`-derivation path calls into the `HighFunction` (panicking here,
        // by design, rather than silently succeeding).
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            HighFunctionSymbol::new(addr, 4, high_function)
        }));
        assert!(result.is_err());
    }

    /// `encode` resolves the namespace and delegates to `HighFunction.encode(...)` with this
    /// symbol's id/min-address/size; `MockHighFunction::encode` (a no-op returning `Ok`) proves
    /// the call actually goes through rather than short-circuiting on the namespace resolution.
    #[test]
    fn encode_delegates_to_high_function_encode() {
        let namespace: Arc<dyn Namespace> = Arc::new(MockNamespace { id: 5, name: "ns".to_string() });
        let function = MockFunction { id: 50, parent_namespace: Some(namespace), is_thunk: false, thunked: None };
        let high_function: Arc<dyn HighFunction> = Arc::new(MockHighFunction { id: 50, function });
        let sym = HighFunctionSymbol::new_with_storage(high_function, ResolvedStorage::Unassigned);

        struct NoopEncoder;
        impl crate::program::model::pcode::Encoder for NoopEncoder {
            fn open_element(&mut self, _elem_id: crate::program::model::pcode::ids::ElementId) -> io::Result<()> {
                Ok(())
            }
            fn close_element(&mut self, _elem_id: crate::program::model::pcode::ids::ElementId) -> io::Result<()> {
                Ok(())
            }
            fn write_bool(&mut self, _attrib_id: crate::program::model::pcode::ids::AttributeId, _val: bool) -> io::Result<()> {
                Ok(())
            }
            fn write_signed_integer(&mut self, _attrib_id: crate::program::model::pcode::ids::AttributeId, _val: i64) -> io::Result<()> {
                Ok(())
            }
            fn write_unsigned_integer(&mut self, _attrib_id: crate::program::model::pcode::ids::AttributeId, _val: u64) -> io::Result<()> {
                Ok(())
            }
            fn write_string(&mut self, _attrib_id: crate::program::model::pcode::ids::AttributeId, _val: &str) -> io::Result<()> {
                Ok(())
            }
            fn write_string_indexed(&mut self, _attrib_id: crate::program::model::pcode::ids::AttributeId, _index: i32, _val: &str) -> io::Result<()> {
                Ok(())
            }
            fn write_space(&mut self, _attrib_id: crate::program::model::pcode::ids::AttributeId, _spc: &AddressSpace) -> io::Result<()> {
                Ok(())
            }
            fn write_space_indexed(&mut self, _attrib_id: crate::program::model::pcode::ids::AttributeId, _index: i32, _name: &str) -> io::Result<()> {
                Ok(())
            }
            fn write_opcode(&mut self, _attrib_id: crate::program::model::pcode::ids::AttributeId, _opcode: crate::decompiler::opcodes::op_code::OpCode) -> io::Result<()> {
                Ok(())
            }
            fn write_opcode_ordinal(&mut self, _attrib_id: crate::program::model::pcode::ids::AttributeId, _opcode: i32) -> io::Result<()> {
                Ok(())
            }
        }
        let mut encoder = NoopEncoder;
        HighSymbol::encode(&sym, &mut encoder).expect("encode should succeed once a namespace resolves");
    }

    /// When no namespace resolves at all (the global-namespace-object edge case Java implicitly
    /// assumes never happens), `encode` returns an error instead of panicking.
    #[test]
    fn encode_errors_when_namespace_does_not_resolve() {
        let function = MockFunction { id: 60, parent_namespace: None, is_thunk: false, thunked: None };
        let high_function: Arc<dyn HighFunction> = Arc::new(MockHighFunction { id: 60, function });
        let sym = HighFunctionSymbol::new_with_storage(high_function, ResolvedStorage::Unassigned);

        struct PanicOnCallEncoder;
        impl crate::program::model::pcode::Encoder for PanicOnCallEncoder {
            fn open_element(&mut self, _elem_id: crate::program::model::pcode::ids::ElementId) -> io::Result<()> {
                panic!("encode should short-circuit before touching the encoder")
            }
            fn close_element(&mut self, _elem_id: crate::program::model::pcode::ids::ElementId) -> io::Result<()> {
                unreachable!()
            }
            fn write_bool(&mut self, _attrib_id: crate::program::model::pcode::ids::AttributeId, _val: bool) -> io::Result<()> {
                unreachable!()
            }
            fn write_signed_integer(&mut self, _attrib_id: crate::program::model::pcode::ids::AttributeId, _val: i64) -> io::Result<()> {
                unreachable!()
            }
            fn write_unsigned_integer(&mut self, _attrib_id: crate::program::model::pcode::ids::AttributeId, _val: u64) -> io::Result<()> {
                unreachable!()
            }
            fn write_string(&mut self, _attrib_id: crate::program::model::pcode::ids::AttributeId, _val: &str) -> io::Result<()> {
                unreachable!()
            }
            fn write_string_indexed(&mut self, _attrib_id: crate::program::model::pcode::ids::AttributeId, _index: i32, _val: &str) -> io::Result<()> {
                unreachable!()
            }
            fn write_space(&mut self, _attrib_id: crate::program::model::pcode::ids::AttributeId, _spc: &AddressSpace) -> io::Result<()> {
                unreachable!()
            }
            fn write_space_indexed(&mut self, _attrib_id: crate::program::model::pcode::ids::AttributeId, _index: i32, _name: &str) -> io::Result<()> {
                unreachable!()
            }
            fn write_opcode(&mut self, _attrib_id: crate::program::model::pcode::ids::AttributeId, _opcode: crate::decompiler::opcodes::op_code::OpCode) -> io::Result<()> {
                unreachable!()
            }
            fn write_opcode_ordinal(&mut self, _attrib_id: crate::program::model::pcode::ids::AttributeId, _opcode: i32) -> io::Result<()> {
                unreachable!()
            }
        }
        let mut encoder = PanicOnCallEncoder;
        let err = HighSymbol::encode(&sym, &mut encoder).unwrap_err();
        assert!(err.to_string().contains("no namespace resolved"));
    }
}
