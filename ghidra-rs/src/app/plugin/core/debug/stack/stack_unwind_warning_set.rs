//! Port of `ghidra.app.plugin.core.debug.stack.StackUnwindWarningSet`.
//!
//! A bucket of warnings. This collects stack unwind warnings and then culls, and combines them
//! for display.
//!
//! # Deviations from Java
//!
//! Java's version wraps a `LinkedHashSet<StackUnwindWarning>`, so it is (nominally) a set: adding
//! an element already present (per `equals`) is a no-op, and `remove`/`contains` use `equals` too.
//! None of the concrete `StackUnwindWarning` implementors override `equals`/`hashCode`, though, so
//! Java's default (reference-identity) equality applies -- in practice, two *separate* warning
//! instances are never "equal" even if they carry the same data, so the `LinkedHashSet` behaves
//! just like an insertion-ordered list that only dedups a literal repeat insertion of the same
//! object. This port models that faithfully: it is backed by a `Vec`, and `contains`/`remove`
//! compare elements by pointer identity (via [`Arc::ptr_eq`]/[`std::ptr::eq`]), matching what
//! Java's identity-based `equals` actually does here.

use std::any::TypeId;
use std::collections::HashSet;
use std::sync::Arc;

use super::stack_unwind_warning::{CustomStackUnwindWarning, StackUnwindWarning};

/// Port of `ghidra.app.plugin.core.debug.stack.StackUnwindWarningSet`.
#[derive(Clone, Default)]
pub struct StackUnwindWarningSet {
    warnings: Vec<Arc<dyn StackUnwindWarning>>,
}

impl StackUnwindWarningSet {
    /// Java: the static factory `StackUnwindWarningSet.custom(String message)`.
    pub fn custom(message: impl Into<String>) -> Self {
        let mut set = Self::new();
        set.add(Arc::new(CustomStackUnwindWarning { message: message.into() }));
        set
    }

    /// Create a new empty set. Java: `StackUnwindWarningSet()`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new set with the given initial warnings. Java: `StackUnwindWarningSet(
    /// StackUnwindWarning... warnings)`.
    pub fn with_warnings(warnings: Vec<Arc<dyn StackUnwindWarning>>) -> Self {
        Self { warnings }
    }

    /// Copy the given set. Java: `StackUnwindWarningSet(Collection<StackUnwindWarning>
    /// warnings)`.
    pub fn from_collection(warnings: &[Arc<dyn StackUnwindWarning>]) -> Self {
        Self { warnings: warnings.to_vec() }
    }

    /// Java: `size()`.
    pub fn size(&self) -> usize {
        self.warnings.len()
    }

    /// Java: `isEmpty()`.
    pub fn is_empty(&self) -> bool {
        self.warnings.is_empty()
    }

    /// Java: `contains(Object)`. See the [module docs](self) for the identity-based comparison
    /// this uses in place of Java's (also effectively identity-based) `equals`.
    pub fn contains(&self, warning: &Arc<dyn StackUnwindWarning>) -> bool {
        self.warnings.iter().any(|w| Arc::ptr_eq(w, warning))
    }

    /// Java: an iterator over the warnings, in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &Arc<dyn StackUnwindWarning>> {
        self.warnings.iter()
    }

    /// The warnings, in insertion order.
    pub fn warnings(&self) -> &[Arc<dyn StackUnwindWarning>] {
        &self.warnings
    }

    /// Java: `add(StackUnwindWarning)`. Returns `true` if the set did not already contain an
    /// (identity-)equal warning.
    pub fn add(&mut self, warning: Arc<dyn StackUnwindWarning>) -> bool {
        if self.contains(&warning) {
            return false;
        }
        self.warnings.push(warning);
        true
    }

    /// Java: `remove(Object)`. Returns `true` if a matching warning was present and removed.
    pub fn remove(&mut self, warning: &Arc<dyn StackUnwindWarning>) -> bool {
        let before = self.warnings.len();
        self.warnings.retain(|w| !Arc::ptr_eq(w, warning));
        self.warnings.len() != before
    }

    /// Java: `addAll(Collection)`.
    pub fn add_all(&mut self, other: &StackUnwindWarningSet) -> bool {
        let mut changed = false;
        for w in &other.warnings {
            if self.add(w.clone()) {
                changed = true;
            }
        }
        changed
    }

    /// Java: `clear()`.
    pub fn clear(&mut self) {
        self.warnings.clear();
    }

    /// Java: `summarize()`.
    ///
    /// This collects stack unwind warnings and then culls, and combines them for display: a
    /// warning that another warning [`StackUnwindWarning::moots`] is dropped entirely; among the
    /// rest, warnings sharing a concrete type that opts into combining (see
    /// [`StackUnwindWarning::combine_group`]) are folded into a single summary line the first
    /// time that type is encountered (and skipped on subsequent encounters); every other warning
    /// contributes its own message.
    pub fn summarize(&self) -> Vec<String> {
        let refs: Vec<&dyn StackUnwindWarning> = self.warnings.iter().map(|w| w.as_ref()).collect();
        let mut combined: HashSet<TypeId> = HashSet::new();
        let mut lines = Vec::new();
        for w in &refs {
            if refs.iter().any(|mw| mw.moots(*w)) {
                continue;
            }
            match w.combine_group(&refs) {
                Some(summary) => {
                    let type_id = w.as_any().type_id();
                    if !combined.insert(type_id) {
                        continue;
                    }
                    lines.push(summary);
                }
                None => lines.push(w.get_message()),
            }
        }
        lines
    }

    /// Java: `reportDetails()`.
    pub fn report_details(&self) {
        for w in &self.warnings {
            w.report_details();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::core::debug::stack::stack_unwind_warning::{
        NoReturnPathStackUnwindWarning, OpaqueReturnPathStackUnwindWarning,
        UnknownPurgeStackUnwindWarning, UnspecifiedConventionStackUnwindWarning,
    };
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::function::Function;
    use crate::program::model::symbol::Namespace;

    fn test_addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    struct MockFunction {
        name: String,
        entry: Address,
    }

    impl Namespace for MockFunction {
        fn get_symbol(&self) -> Arc<dyn crate::program::model::symbol::Symbol> {
            unimplemented!()
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            None
        }
    }

    impl Function for MockFunction {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn set_name(&mut self, _name: &str, _source: crate::program::model::symbol::SourceType) -> Result<(), crate::program::model::listing::function::SetFunctionNameError> {
            Ok(())
        }

        fn set_call_fixup(&mut self, _name: Option<&str>) {}

        fn get_call_fixup(&self) -> Option<String> {
            None
        }

        fn get_program(&self) -> Arc<dyn crate::program::model::listing::Program> {
            unimplemented!()
        }

        fn get_comment(&self) -> Option<String> {
            None
        }

        fn get_comment_as_array(&self) -> Vec<String> {
            vec![]
        }

        fn set_comment(&mut self, _comment: Option<&str>) {}

        fn get_repeatable_comment(&self) -> Option<String> {
            None
        }

        fn get_repeatable_comment_as_array(&self) -> Vec<String> {
            vec![]
        }

        fn set_repeatable_comment(&mut self, _comment: Option<&str>) {}

        fn get_entry_point(&self) -> Address {
            self.entry.clone()
        }

        fn get_return_type(&self) -> Option<Box<dyn crate::program::model::data::data_type::DataType>> {
            None
        }

        fn set_return_type(
            &mut self,
            _data_type: Box<dyn crate::program::model::data::data_type::DataType>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            Ok(())
        }

        fn get_return(&self) -> Box<dyn crate::program::model::listing::Parameter> {
            unimplemented!()
        }

        fn set_return(
            &mut self,
            _data_type: Box<dyn crate::program::model::data::data_type::DataType>,
            _storage: Box<dyn crate::program::model::listing::variable_storage::VariableStorage>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            Ok(())
        }

        fn get_signature_formal(&self, _formal_signature: bool) -> Box<dyn crate::program::model::listing::FunctionSignature> {
            unimplemented!()
        }

        fn get_prototype_string(&self, _formal_signature: bool, _include_calling_convention: bool) -> String {
            String::new()
        }

        fn get_signature_source(&self) -> crate::program::model::symbol::SourceType {
            unimplemented!()
        }

        fn set_signature_source(&mut self, _signature_source: crate::program::model::symbol::SourceType) {}

        fn get_stack_frame(&self) -> Box<dyn crate::program::seam_stubs::StackFrame> {
            unimplemented!()
        }

        fn get_stack_purge_size(&self) -> i32 {
            0
        }

        fn get_tags(&self) -> Vec<Box<dyn crate::program::model::listing::FunctionTag>> {
            vec![]
        }

        fn add_tag(&mut self, _name: &str) -> bool {
            true
        }

        fn remove_tag(&mut self, _name: &str) {}

        fn set_stack_purge_size(&mut self, _purge_size: i32) {}

        fn is_stack_purge_size_valid(&self) -> bool {
            true
        }

        fn add_parameter(
            &mut self,
            _var: Box<dyn crate::program::model::listing::Variable>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<Box<dyn crate::program::model::listing::Parameter>, crate::program::model::listing::function::FunctionEditError> {
            unimplemented!()
        }

        fn insert_parameter(
            &mut self,
            _ordinal: i32,
            _var: Box<dyn crate::program::model::listing::Variable>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<Box<dyn crate::program::model::listing::Parameter>, crate::program::model::listing::function::FunctionEditError> {
            unimplemented!()
        }

        fn replace_parameters(
            &mut self,
            _params: Vec<Box<dyn crate::program::model::listing::Variable>>,
            _update_type: crate::program::model::listing::FunctionUpdateType,
            _force: bool,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::program::model::listing::function::FunctionEditError> {
            Ok(())
        }

        fn update_function(
            &mut self,
            _calling_convention: Option<&str>,
            _return_value: Option<Box<dyn crate::program::model::listing::Variable>>,
            _new_params: Vec<Box<dyn crate::program::model::listing::Variable>>,
            _update_type: crate::program::model::listing::FunctionUpdateType,
            _force: bool,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::program::model::listing::function::FunctionEditError> {
            Ok(())
        }

        fn get_parameters(&self) -> Vec<Box<dyn crate::program::model::listing::Parameter>> {
            vec![]
        }

        fn get_parameter(&self, _ordinal: i32) -> Option<Box<dyn crate::program::model::listing::Parameter>> {
            None
        }

        fn get_parameter_count(&self) -> i32 {
            0
        }

        fn get_local_variables(&self) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            vec![]
        }

        fn add_local_variable(
            &mut self,
            _var: Box<dyn crate::program::model::listing::Variable>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<Box<dyn crate::program::model::listing::Variable>, crate::program::model::listing::function::FunctionEditError> {
            unimplemented!()
        }

        fn remove_variable(&mut self, _var: &dyn crate::program::model::listing::Variable) {}

        fn get_parameters_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn crate::program::model::listing::Parameter>> {
            vec![]
        }

        fn get_local_variables_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            vec![]
        }

        fn get_variables_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            vec![]
        }

        fn get_all_variables(&self) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            vec![]
        }

        fn get_auto_parameter_count(&self) -> i32 {
            0
        }

        #[allow(deprecated)]
        fn remove_parameter(&mut self, _ordinal: i32) {}

        #[allow(deprecated)]
        fn move_parameter(
            &mut self,
            _from_ordinal: i32,
            _to_ordinal: i32,
        ) -> Result<Box<dyn crate::program::model::listing::Parameter>, crate::util::exception::InvalidInputException> {
            unimplemented!()
        }

        fn has_custom_variable_storage(&self) -> bool {
            false
        }

        fn set_custom_variable_storage(&mut self, _custom_storage: bool) {}

        fn is_external(&self) -> bool {
            false
        }

        fn get_external_location(&self) -> Option<Box<dyn crate::program::model::symbol::ExternalLocation>> {
            None
        }

        fn get_thunked_function(&self, _recursive: bool) -> Option<Arc<dyn Function>> {
            None
        }

        fn set_thunked_function(&mut self, _thunked_function: Option<Arc<dyn Function>>) -> Result<(), String> {
            Ok(())
        }

        fn get_function_thunk_addresses(&self, _recursive: bool) -> Option<Vec<Address>> {
            None
        }

        fn is_thunk(&self) -> bool {
            false
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

        fn get_calling_convention(&self) -> Option<Box<dyn crate::program::model::lang::prototype_model::PrototypeModel>> {
            None
        }

        fn get_calling_convention_name(&self) -> String {
            String::from("unknown")
        }

        fn set_calling_convention(&mut self, _name: &str) -> Result<(), crate::util::exception::InvalidInputException> {
            Ok(())
        }

        fn get_calling_functions(&self, _monitor: &dyn crate::util::task::TaskMonitor) -> Vec<Arc<dyn Function>> {
            vec![]
        }

        fn get_called_functions(&self, _monitor: &dyn crate::util::task::TaskMonitor) -> Vec<Arc<dyn Function>> {
            vec![]
        }

        fn set_body(&mut self, _new_body: &dyn crate::program::model::address::AddressSetView) -> Result<(), crate::program::database::function::OverlappingFunctionException> {
            Ok(())
        }

        fn promote_local_user_labels_to_global(&mut self) {}

        fn is_deleted(&self) -> bool {
            false
        }
    }

    fn func(name: &str) -> Box<dyn Function> {
        Box::new(MockFunction { name: name.to_string(), entry: test_addr(0) })
    }

    #[test]
    fn new_set_is_empty() {
        let set = StackUnwindWarningSet::new();
        assert!(set.is_empty());
        assert_eq!(set.size(), 0);
        assert!(set.summarize().is_empty());
    }

    #[test]
    fn custom_creates_a_single_custom_warning() {
        let set = StackUnwindWarningSet::custom("oops");
        assert_eq!(set.size(), 1);
        assert_eq!(set.summarize(), vec!["oops".to_string()]);
    }

    #[test]
    fn add_returns_false_for_the_same_arc_twice() {
        let mut set = StackUnwindWarningSet::new();
        let w: Arc<dyn StackUnwindWarning> =
            Arc::new(NoReturnPathStackUnwindWarning { pc: test_addr(0x1000) });
        assert!(set.add(w.clone()));
        assert!(!set.add(w.clone()), "adding the identical Arc again must be a no-op");
        assert_eq!(set.size(), 1);
    }

    #[test]
    fn add_does_not_dedup_distinct_instances_with_equal_content() {
        // Faithful to Java: no StackUnwindWarning subtype overrides equals(), so two separate
        // instances are never considered equal even with identical fields.
        let mut set = StackUnwindWarningSet::new();
        let a: Arc<dyn StackUnwindWarning> =
            Arc::new(NoReturnPathStackUnwindWarning { pc: test_addr(0x1000) });
        let b: Arc<dyn StackUnwindWarning> =
            Arc::new(NoReturnPathStackUnwindWarning { pc: test_addr(0x1000) });
        assert!(set.add(a));
        assert!(set.add(b));
        assert_eq!(set.size(), 2);
    }

    #[test]
    fn remove_and_contains_use_identity() {
        let mut set = StackUnwindWarningSet::new();
        let a: Arc<dyn StackUnwindWarning> =
            Arc::new(NoReturnPathStackUnwindWarning { pc: test_addr(0x1000) });
        let b: Arc<dyn StackUnwindWarning> =
            Arc::new(NoReturnPathStackUnwindWarning { pc: test_addr(0x1000) });
        set.add(a.clone());
        assert!(set.contains(&a));
        assert!(!set.contains(&b));
        assert!(set.remove(&a));
        assert!(set.is_empty());
        assert!(!set.remove(&a), "already removed");
    }

    #[test]
    fn add_all_merges_another_set() {
        let mut set = StackUnwindWarningSet::custom("a");
        let other = StackUnwindWarningSet::custom("b");
        assert!(set.add_all(&other));
        assert_eq!(set.size(), 2);
        assert_eq!(set.summarize(), vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn clear_empties_the_set() {
        let mut set = StackUnwindWarningSet::custom("a");
        set.clear();
        assert!(set.is_empty());
    }

    #[test]
    fn summarize_drops_a_mooted_warning() {
        let mut set = StackUnwindWarningSet::new();
        let pc = test_addr(0x1000);
        set.add(Arc::new(NoReturnPathStackUnwindWarning { pc: pc.clone() }));
        set.add(Arc::new(OpaqueReturnPathStackUnwindWarning {
            pc,
            last: Box::new(crate::app::plugin::core::debug::stack::unwind_exception::UnwindException::new(
                "boom",
            )),
        }));
        // NoReturnPathStackUnwindWarning::moots returns true for an
        // OpaqueReturnPathStackUnwindWarning, so only the "no return path" message should survive.
        let lines = set.summarize();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("Could not find a path from"));
    }

    #[test]
    fn summarize_folds_multiple_combinable_warnings_of_the_same_type() {
        let mut set = StackUnwindWarningSet::new();
        set.add(Arc::new(UnknownPurgeStackUnwindWarning { function: func("foo") }));
        set.add(Arc::new(UnknownPurgeStackUnwindWarning { function: func("bar") }));
        let lines = set.summarize();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], "Functions bar, foo have unknown/invalid stack purge.");
    }

    #[test]
    fn summarize_reports_a_singleton_combinable_warning_via_its_own_message() {
        let mut set = StackUnwindWarningSet::new();
        set.add(Arc::new(UnknownPurgeStackUnwindWarning { function: func("solo") }));
        let lines = set.summarize();
        assert_eq!(lines, vec!["Function solo has unknown/invalid stack purge".to_string()]);
    }

    #[test]
    fn summarize_keeps_different_combinable_types_separate() {
        let mut set = StackUnwindWarningSet::new();
        set.add(Arc::new(UnknownPurgeStackUnwindWarning { function: func("foo") }));
        set.add(Arc::new(UnknownPurgeStackUnwindWarning { function: func("bar") }));
        set.add(Arc::new(UnspecifiedConventionStackUnwindWarning { function: func("baz") }));
        let lines = set.summarize();
        assert_eq!(lines.len(), 2);
        assert!(lines.iter().any(|l| l.contains("unknown/invalid stack purge")));
        assert!(lines.iter().any(|l| l.contains("unspecified convention")));
    }

    #[test]
    fn summarize_mixes_combined_and_standalone_messages() {
        let mut set = StackUnwindWarningSet::new();
        set.add(Arc::new(UnknownPurgeStackUnwindWarning { function: func("foo") }));
        set.add(Arc::new(UnknownPurgeStackUnwindWarning { function: func("bar") }));
        set.add(Arc::new(CustomStackUnwindWarning { message: "standalone".to_string() }));
        let lines = set.summarize();
        assert_eq!(lines.len(), 2);
        assert!(lines.contains(&"standalone".to_string()));
    }

    #[test]
    fn report_details_does_not_panic_on_a_mix_of_warnings() {
        let mut set = StackUnwindWarningSet::new();
        set.add(Arc::new(CustomStackUnwindWarning { message: "a".to_string() }));
        set.add(Arc::new(UnknownPurgeStackUnwindWarning { function: func("foo") }));
        set.report_details();
    }

    #[test]
    fn clone_produces_an_independent_but_equal_snapshot() {
        let set = StackUnwindWarningSet::custom("a");
        let cloned = set.clone();
        assert_eq!(cloned.size(), set.size());
        assert_eq!(cloned.summarize(), set.summarize());
    }
}
