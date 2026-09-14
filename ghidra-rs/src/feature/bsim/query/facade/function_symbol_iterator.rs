//! Port of `ghidra.features.bsim.query.facade.FunctionSymbolIterator`.

use std::sync::Arc;

use crate::program::database::symbol::FunctionSymbol;
use crate::program::model::listing::Function;

/// Converts an iterator over `FunctionSymbol`s into an iterator over `Function`s.
///
/// Port of `ghidra.features.bsim.query.facade.FunctionSymbolIterator`. Java implements
/// `Iterator<Function>` by wrapping an `Iterator<FunctionSymbol>`; here [`FunctionSymbolIterator`]
/// implements Rust's [`Iterator`] directly, generic over the wrapped iterator `I` -- the idiomatic
/// equivalent already established elsewhere in this crate for the same situation (see
/// [`FilteredIterator`](crate::generic::filtered_iterator::FilteredIterator)'s own doc comment).
///
/// # `Item = Option<Arc<dyn Function>>`, not `Arc<dyn Function>`
///
/// Java's `next()` can legitimately return `null` *without* the iteration having ended: either
/// the wrapped `Iterator<FunctionSymbol>` itself yields a `null` element (Java's raw
/// `Iterator<FunctionSymbol>` type permits this, unlike Rust's `Iterator::Item`, which is never
/// itself optional here -- hence `I::Item = Option<Arc<dyn FunctionSymbol>>`, modeling the
/// possibility directly), or a non-null `FunctionSymbol` resolves to no live `Function` via
/// `FunctionSymbol.getObject()`. Rust's `Iterator::next()` reserves `None` to mean "iteration
/// exhausted", so a bare `Item = Arc<dyn Function>` couldn't distinguish "no more elements" from
/// "this element is null" the way Java's `hasNext()`/`next()` pair can. Wrapping the item in an
/// extra `Option` keeps that distinction: the *outer* `Option` (from `Iterator::next` itself)
/// means "exhausted", the *inner* one mirrors Java's possibly-null `Function` result.
///
/// # `remove()` omitted
///
/// Java's `remove()` override is a no-op ("not functional"; the comment is the entire method
/// body), so there is no real behavior to preserve by adding a matching method here.
pub struct FunctionSymbolIterator<I>
where
    I: Iterator<Item = Option<Arc<dyn FunctionSymbol>>>,
{
    sym_iter: I,
}

impl<I> FunctionSymbolIterator<I>
where
    I: Iterator<Item = Option<Arc<dyn FunctionSymbol>>>,
{
    /// Port of `FunctionSymbolIterator(Iterator<FunctionSymbol> iter)`.
    pub fn new(iter: I) -> Self {
        FunctionSymbolIterator { sym_iter: iter }
    }
}

impl<I> Iterator for FunctionSymbolIterator<I>
where
    I: Iterator<Item = Option<Arc<dyn FunctionSymbol>>>,
{
    type Item = Option<Arc<dyn Function>>;

    /// Port of `next()`:
    ///
    /// ```java
    /// public Function next() {
    ///     FunctionSymbol sym = symiter.next();
    ///     if (sym == null) return null;
    ///     Object obj = sym.getObject();
    ///     if (obj == null) return null;
    ///     return (Function) obj;
    /// }
    /// ```
    fn next(&mut self) -> Option<Self::Item> {
        let sym = self.sym_iter.next()?;
        match sym {
            None => Some(None),
            Some(sym) => Some(sym.get_object()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::database::function::OverlappingFunctionException;
    use crate::program::model::address::Address;
    use crate::program::model::listing::function::{FunctionEditError, FunctionUpdateType, SetFunctionNameError};
    use crate::program::model::listing::{FunctionSignature, FunctionTag, Parameter, Program, Variable};
    use crate::program::model::symbol::{Namespace, SetParentNamespaceError, SourceType, Symbol, SymbolType};
    use crate::util::task::TaskMonitor;

    /// Minimal `Function` mock: only `get_name` is exercised by these tests (to distinguish
    /// which function round-tripped through the iterator); every other method is unreachable
    /// from the tests below, so it panics if ever called, matching the established convention
    /// for "not exercised by this smoke test" mocks elsewhere in this crate.
    struct MockFunction {
        name: &'static str,
    }

    impl Namespace for MockFunction {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            None
        }
    }

    impl Function for MockFunction {
        fn get_name(&self) -> String {
            self.name.to_string()
        }
        fn set_name(&mut self, _name: &str, _source: SourceType) -> Result<(), SetFunctionNameError> {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_call_fixup(&mut self, _name: Option<&str>) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_call_fixup(&self) -> Option<String> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_comment(&self) -> Option<String> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_comment_as_array(&self) -> Vec<String> {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_comment(&mut self, _comment: Option<&str>) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_repeatable_comment(&self) -> Option<String> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_repeatable_comment_as_array(&self) -> Vec<String> {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_repeatable_comment(&mut self, _comment: Option<&str>) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_entry_point(&self) -> Address {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_return_type(&self) -> Option<Box<dyn crate::program::model::data::data_type::DataType>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_return_type(
            &mut self,
            _data_type: Box<dyn crate::program::model::data::data_type::DataType>,
            _source: SourceType,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_return(&self) -> Box<dyn Parameter> {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_return(
            &mut self,
            _data_type: Box<dyn crate::program::model::data::data_type::DataType>,
            _storage: Box<dyn crate::program::model::listing::variable_storage::VariableStorage>,
            _source: SourceType,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_signature_formal(&self, _formal_signature: bool) -> Box<dyn FunctionSignature> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_prototype_string(&self, _formal_signature: bool, _include_calling_convention: bool) -> String {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_signature_source(&self) -> SourceType {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_signature_source(&mut self, _signature_source: SourceType) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_stack_frame(&self) -> Box<dyn crate::program::seam_stubs::StackFrame> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_stack_purge_size(&self) -> i32 {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_tags(&self) -> Vec<Box<dyn FunctionTag>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn add_tag(&mut self, _name: &str) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn remove_tag(&mut self, _name: &str) {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_stack_purge_size(&mut self, _purge_size: i32) {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_stack_purge_size_valid(&self) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        #[allow(deprecated)]
        fn add_parameter(
            &mut self,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Parameter>, FunctionEditError> {
            unimplemented!("not exercised by this smoke test")
        }
        #[allow(deprecated)]
        fn insert_parameter(
            &mut self,
            _ordinal: i32,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Parameter>, FunctionEditError> {
            unimplemented!("not exercised by this smoke test")
        }
        fn replace_parameters(
            &mut self,
            _params: Vec<Box<dyn Variable>>,
            _update_type: FunctionUpdateType,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), FunctionEditError> {
            unimplemented!("not exercised by this smoke test")
        }
        fn update_function(
            &mut self,
            _calling_convention: Option<&str>,
            _return_value: Option<Box<dyn Variable>>,
            _new_params: Vec<Box<dyn Variable>>,
            _update_type: FunctionUpdateType,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), FunctionEditError> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_parameter(&self, _ordinal: i32) -> Option<Box<dyn Parameter>> {
            unimplemented!("not exercised by this smoke test")
        }
        #[allow(deprecated)]
        fn remove_parameter(&mut self, _ordinal: i32) {
            unimplemented!("not exercised by this smoke test")
        }
        #[allow(deprecated)]
        fn move_parameter(
            &mut self,
            _from_ordinal: i32,
            _to_ordinal: i32,
        ) -> Result<Box<dyn Parameter>, crate::util::exception::InvalidInputException> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_parameter_count(&self) -> i32 {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_auto_parameter_count(&self) -> i32 {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_parameters(&self) -> Vec<Box<dyn Parameter>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_parameters_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn Parameter>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_local_variables(&self) -> Vec<Box<dyn Variable>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_local_variables_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn Variable>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_variables_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn Variable>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_all_variables(&self) -> Vec<Box<dyn Variable>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn add_local_variable(
            &mut self,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Variable>, FunctionEditError> {
            unimplemented!("not exercised by this smoke test")
        }
        fn remove_variable(&mut self, _var: &dyn Variable) {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_body(
            &mut self,
            _new_body: &dyn crate::program::model::address::AddressSetView,
        ) -> Result<(), OverlappingFunctionException> {
            unimplemented!("not exercised by this smoke test")
        }
        fn has_var_args(&self) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_var_args(&mut self, _has_var_args: bool) {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_inline(&self) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_inline(&mut self, _is_inline: bool) {
            unimplemented!("not exercised by this smoke test")
        }
        fn has_no_return(&self) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_no_return(&mut self, _has_no_return: bool) {
            unimplemented!("not exercised by this smoke test")
        }
        fn has_custom_variable_storage(&self) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_custom_variable_storage(&mut self, _has_custom_variable_storage: bool) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_calling_convention(
            &self,
        ) -> Option<Box<dyn crate::program::model::lang::prototype_model::PrototypeModel>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_calling_convention_name(&self) -> String {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_calling_convention(&mut self, _name: &str) -> Result<(), crate::util::exception::InvalidInputException> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_thunk(&self) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_thunked_function(&self, _recursive: bool) -> Option<Arc<dyn Function>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_function_thunk_addresses(&self, _recursive: bool) -> Option<Vec<Address>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_thunked_function(&mut self, _thunked_function: Option<Arc<dyn Function>>) -> Result<(), String> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_external(&self) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_external_location(&self) -> Option<Box<dyn crate::program::model::symbol::ExternalLocation>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_calling_functions(&self, _monitor: &dyn TaskMonitor) -> Vec<Arc<dyn Function>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_called_functions(&self, _monitor: &dyn TaskMonitor) -> Vec<Arc<dyn Function>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn promote_local_user_labels_to_global(&mut self) {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_deleted(&self) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
    }

    struct MockProgram;
    impl DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    /// A minimal `FunctionSymbol` mock: `get_object()` returns whatever was configured at
    /// construction time, either a live [`MockFunction`] or `None` (the "symbol resolves to no
    /// live Function" case). Every other method is unreachable from these tests.
    struct MockFunctionSymbol {
        object: Option<Arc<dyn Function>>,
    }

    impl Symbol for MockFunctionSymbol {
        fn get_address(&self) -> Address {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_name(&self) -> &str {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Function
        }
        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            0
        }
        fn get_parent_id(&self) -> i64 {
            0
        }
        fn get_program(&self) -> Option<Arc<dyn Program>> {
            Some(Arc::new(MockProgram))
        }
    }

    impl FunctionSymbol for MockFunctionSymbol {
        fn set_name_and_namespace(
            &mut self,
            _new_name: &str,
            _new_namespace: Arc<dyn Namespace>,
            _source: SourceType,
        ) -> Result<(), SetParentNamespaceError> {
            unimplemented!("not exercised by this smoke test")
        }
        fn delete(&mut self) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_object(&self) -> Option<Arc<dyn Function>> {
            self.object.clone()
        }
        fn get_program_location(&self) -> Option<Box<dyn crate::program::util::ProgramLocation>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_valid_parent(&self, _parent: &dyn Namespace) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_thunked_symbol(&self) -> Option<Arc<dyn Symbol>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn thunk_symbols(&self) -> Vec<Arc<dyn Symbol>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn validate_name_source(&self, _new_name: Option<&str>, source: SourceType) -> SourceType {
            source
        }
        fn base_reference_count(&self) -> i32 {
            unimplemented!("not exercised by this smoke test")
        }
        fn base_has_references(&self) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn base_references(
            &self,
            _monitor: &dyn TaskMonitor,
        ) -> Vec<Arc<dyn crate::program::model::symbol::Reference>> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    fn sym_with_function(name: &'static str) -> Option<Arc<dyn FunctionSymbol>> {
        Some(Arc::new(MockFunctionSymbol { object: Some(Arc::new(MockFunction { name })) }))
    }

    fn sym_without_function() -> Option<Arc<dyn FunctionSymbol>> {
        Some(Arc::new(MockFunctionSymbol { object: None }))
    }

    #[test]
    fn yields_functions_resolved_from_each_symbol() {
        let syms: Vec<Option<Arc<dyn FunctionSymbol>>> =
            vec![sym_with_function("foo"), sym_with_function("bar")];
        let mut iter = FunctionSymbolIterator::new(syms.into_iter());

        let first = iter.next().unwrap().unwrap();
        assert_eq!(Function::get_name(first.as_ref()), "foo");
        let second = iter.next().unwrap().unwrap();
        assert_eq!(Function::get_name(second.as_ref()), "bar");
        assert!(iter.next().is_none());
    }

    #[test]
    fn null_object_yields_none_without_ending_iteration() {
        // FunctionSymbol.getObject() == null: Java's next() returns null, but hasNext() may
        // still be true for the next call -- reproduced here as Some(None) rather than the
        // iterator-exhausted None. `dyn Function` has no `Debug` impl, so `matches!` is used
        // instead of `assert_eq!` (which would additionally require `Debug`).
        let syms: Vec<Option<Arc<dyn FunctionSymbol>>> =
            vec![sym_without_function(), sym_with_function("after")];
        let mut iter = FunctionSymbolIterator::new(syms.into_iter());

        assert!(matches!(iter.next(), Some(None)));
        let second = iter.next().unwrap().unwrap();
        assert_eq!(Function::get_name(second.as_ref()), "after");
        assert!(iter.next().is_none());
    }

    #[test]
    fn null_symbol_yields_none_without_ending_iteration() {
        // The wrapped Iterator<FunctionSymbol> itself yielding a null element (`sym == null` in
        // Java) is likewise not iteration-ending.
        let syms: Vec<Option<Arc<dyn FunctionSymbol>>> = vec![None, sym_with_function("after")];
        let mut iter = FunctionSymbolIterator::new(syms.into_iter());

        assert!(matches!(iter.next(), Some(None)));
        let second = iter.next().unwrap().unwrap();
        assert_eq!(Function::get_name(second.as_ref()), "after");
    }

    #[test]
    fn empty_source_iterator_is_immediately_exhausted() {
        let syms: Vec<Option<Arc<dyn FunctionSymbol>>> = Vec::new();
        let mut iter = FunctionSymbolIterator::new(syms.into_iter());
        assert!(iter.next().is_none());
    }

    #[test]
    fn standard_iterator_adapters_work() {
        let syms: Vec<Option<Arc<dyn FunctionSymbol>>> =
            vec![sym_with_function("a"), sym_without_function(), sym_with_function("b")];
        let names: Vec<String> = FunctionSymbolIterator::new(syms.into_iter())
            .flatten()
            .map(|f| Function::get_name(f.as_ref()))
            .collect();
        assert_eq!(names, vec!["a".to_string(), "b".to_string()]);
    }
}
